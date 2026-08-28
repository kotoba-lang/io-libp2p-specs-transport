(ns libp2p.provider.node-muxed
  "Yamux over the Noise-secured socket, driven by Node's async `net.Socket` —
  the piece `libp2p.provider.node/dial!` stops short of.

  `kotoba.net.libp2p.connection` already implements this whole stack
  (multistream → Noise XX → multistream → Yamux → per-stream multistream),
  correctly and with tests, but as a **synchronous** `{:read! :write!}` port:
  `read!` blocks the calling thread until N octets exist. That is exactly what
  a JVM `Socket`'s blocking streams give you for free, and exactly what a
  Node.js `net.Socket` cannot: the event loop is how MORE bytes ever arrive, so
  a `read!` that busy-waits on it never sees them arrive.

  So this namespace does not reuse `connection.cljc`'s port — it reimplements
  its control flow as a promise-driven poll, the same technique
  `libp2p.provider.node/read-until!` already uses for the Noise handshake, one
  layer further up. What IS reused, unchanged, is every *pure* decision:
  `libp2p.multistream`, `libp2p.yamux`, `noise.cipher-state`'s AEAD, and
  `libp2p.provider.node`'s own frame predicates (`take-ms-message!`,
  `take-noise-frame!` — both already generic over 'some atom holding buffered
  octets', not tied to the raw socket inbox). Only the *pump* — what decides
  when to try decrypting one more Noise frame vs. wait for one more TCP
  packet — is new.

  ## Two pump depths, because Yamux itself is negotiated

  Before `/yamux/1.0.0` is accepted, plaintext flowing over the secure channel
  is raw multistream text — there is no muxer yet, so nothing on it is
  Yamux-framed. `presecure-step-until!` only ever decrypts Noise frames into
  `plain-buf` and re-checks a predicate against the raw bytes.

  After acceptance, EVERY plaintext octet is inside a Yamux frame — including
  the per-stream multistream negotiation for whatever protocol a stream
  carries. `step-until!` adds the frame-dispatch layer: decode one Yamux frame
  off `plain-buf`, route it (ping→ack, go-away, reset an unrecognised inbound
  SYN, or append DATA to the owning stream's own buffer), and only fall back to
  decrypting another Noise frame once `plain-buf` holds no complete frame.
  Using the framed poller before the muxer exists would try to parse a
  multistream string's length-prefix byte as a Yamux version octet and fail
  the connection on the first read."
  (:require [clojure.string :as str]
            ["@noble/curves/ed25519.js" :refer [ed25519]]
            [libp2p.multistream :as ms]
            [libp2p.provider.node :as node]
            [libp2p.yamux :as yamux]
            [noise.cipher-state :as cs]
            [noise.core :as noise]))

(def yamux-protocol "/yamux/1.0.0")
(def max-noise-message 65535)

;; ── varint-length-prefixed message framing (msgio) ─────────────────────────
;; identify / kad / bitswap all send exactly one protobuf message per read,
;; each prefixed with its byte length as a plain (non-multistream) varint —
;; distinct from BOTH the multistream varint-prefixed-string framing and the
;; Yamux 12-octet header. Confirmed against this workspace's own JVM dialer
;; (`kotoba.net.libp2p.dial/identify!`), which reads the length one octet at a
;; time off the stream before decoding the protobuf body the same way.

(defn- decode-varint-prefix
  "One varint-length-prefixed message off `bs`, or nil if incomplete. Running
  past the buffer's end is the ordinary 'need more octets' case a streaming
  reader hits constantly, not a malformed message — unlike
  `protobuf.wire/decode-varint`, which is handed a complete buffer and treats
  the same situation as truncation."
  [bs]
  (let [bs (vec bs)]
    (loop [i 0 shift 0 acc 0]
      (cond
        (>= i (count bs)) nil
        (> shift 63) (throw (js/Error. "varint-prefix: too many groups"))
        :else
        (let [b (bit-and (nth bs i) 0xFF)
              acc (bit-or acc (bit-shift-left (bit-and b 0x7F) shift))
              i' (inc i)]
          (if (zero? (bit-and b 0x80))
            (when (>= (count bs) (+ i' acc))
              {:message (subvec bs i' (+ i' acc)) :rest (subvec bs (+ i' acc))})
            (recur i' (+ shift 7) acc)))))))

(defn take-length-prefixed-message!
  "Pred: one varint-length-prefixed message off a per-stream buffer atom."
  [buf]
  (fn [bs]
    (let [r (decode-varint-prefix bs)]
      (when r (reset! buf (:rest r)) (:message r)))))

(defn- put-varint [n]
  (loop [v n out []]
    (if (< v 0x80) (conj out v) (recur (quot v 128) (conj out (bit-or (bit-and v 0x7F) 0x80))))))

(defn length-prefix [octets] (into (put-varint (count octets)) (vec octets)))

;; ── Yamux frame predicate over the shared plaintext buffer ─────────────────

(defn take-yamux-frame!
  "Pred: one Yamux frame off `buf`, the single plaintext buffer shared by the
  whole muxed session (frames for every open stream interleave on it)."
  [buf]
  (fn [bs]
    (let [{:keys [frame rest error]} (yamux/decode (vec bs))]
      (when error (throw (js/Error. (str "yamux: " error))))
      (when frame (reset! buf rest) frame))))

;; ── connection context ──────────────────────────────────────────────────────

(defn- session-ctx [conn role]
  {:conn conn
   :send-cs (atom nil)
   :recv-cs (atom nil)
   :plain-buf (atom [])
   :session (atom (yamux/session role))
   :streams (atom {})               ; stream-id -> plaintext buffer atom
   :closed? (atom false)})

(defn secure-write!
  "Encrypt OCTETS as one or more Noise transport messages and write them to
  the raw socket. `max-noise-message - 16` leaves room for the AEAD tag, same
  budget `kotoba.net.libp2p.connection/secure-port` uses."
  [ctx octets]
  (doseq [chunk (partition-all (- max-noise-message 16) (vec octets))]
    (let [[next-cs ct] (cs/encrypt-with-ad @(:send-cs ctx) [] (vec chunk))]
      (reset! (:send-cs ctx) next-cs)
      (node/write-noise! (:conn ctx) ct))))

(defn- decrypt-one-noise-frame!
  "Try to take exactly one already-buffered Noise frame off the raw TCP inbox
  and fold its plaintext into `plain-buf`. `{:decrypted true}` on success,
  `{:decrypted false}` when the raw inbox does not yet hold a whole frame —
  never throws for 'not enough bytes yet', only for a malformed frame."
  [ctx]
  (let [conn (:conn ctx)
        frame ((node/take-noise-frame! (:inbox conn)) @(:inbox conn))]
    (if frame
      (let [[next-cs plain] (cs/decrypt-with-ad @(:recv-cs ctx) [] frame)]
        (reset! (:recv-cs ctx) next-cs)
        (swap! (:plain-buf ctx) into plain)
        {:decrypted true})
      {:decrypted false})))

(defn- retry-or-fail!
  "Neither `pred` nor `advance!` made progress this tick: decide whether that
  is because the peer/socket has nothing more to give (fail now, via `fail!`)
  or because more TCP bytes may still arrive (wait, then call `tick` again)."
  [fail! conn t0 timeout-ms tick]
  (let [s @(:state conn)]
    (cond
      (:error s) (fail! (str "socket error: " (:error s)))
      (and (:closed s) (empty? @(:inbox conn))) (fail! "peer closed with nothing buffered")
      (> (- (js/Date.now) t0) timeout-ms) (fail! (str "timeout after " timeout-ms "ms"))
      :else (js/setTimeout tick 15))))

(defn- poll-loop!
  "Shared timeout/error/backoff plumbing for both pump depths. `advance!` is
  called each tick that `pred` is not yet satisfied; it must itself try to
  make progress (decrypt a frame, dispatch a Yamux frame, ...) and return
  truthy if it did, so the caller retries `pred` immediately instead of
  waiting out the poll interval."
  [ctx pred advance! timeout-ms label]
  (js/Promise.
   (fn [resolve reject]
     (let [t0 (js/Date.now)
           conn (:conn ctx)
           fail! (fn [msg] (reject (js/Error. (str label ": " msg))))]
       (letfn [(tick []
                 (let [ok (try (pred)
                               (catch :default e (fail! (or (.-message e) (str e))) ::stop))]
                   (cond
                     (= ok ::stop) nil
                     ok (resolve ok)
                     :else
                     (let [progressed? (try (boolean (advance!))
                                             (catch :default e (fail! (or (.-message e) (str e))) ::stop))]
                       (cond
                         (= progressed? ::stop) nil
                         progressed? (tick)
                         :else (retry-or-fail! fail! conn t0 timeout-ms tick))))))]
         (tick))))))

(defn presecure-step-until!
  "Poll before the muxer exists: `pred` sees raw (un-Yamux-framed) plaintext."
  [ctx pred timeout-ms label]
  (poll-loop! ctx pred #(:decrypted (decrypt-one-noise-frame! ctx)) timeout-ms label))

(defn- dispatch-one-yamux-frame!
  "Take and route one Yamux frame off `plain-buf`, if a complete one is
  already buffered. Returns truthy iff it dispatched one.

  Mirrors `kotoba.net.libp2p.connection/pump!`'s policy exactly (ping→ack,
  go-away, reset an inbound SYN this side did not open, append DATA to the
  owning stream) — reimplemented against atoms rather than `vswap!`/`vreset!`
  because this pump is reentered from promise continuations, not one
  synchronous call stack."
  [ctx]
  (if-let [frame ((take-yamux-frame! (:plain-buf ctx)) @(:plain-buf ctx))]
    (let [{:keys [type stream-id flags]} frame]
      (when js/process.env.MUXED_DEBUG
        (println "DEBUG frame:" type "stream" stream-id "flags" flags
                 "payload-len" (count (:payload frame))
                 "known-streams" (keys @(:streams ctx))))
      (cond
        (= :ping type)
        (when-not (contains? flags :ack)
          (secure-write! ctx (yamux/ping (:length frame) :ack? true)))

        (= :go-away type)
        (reset! (:closed? ctx) true)

        ;; The initiating SYN of an inbound stream this side did not open. The
        ;; Yamux spec (and go-libp2p's implementation of it) allows SYN on
        ;; EITHER a DATA frame or a zero-delta WINDOW_UPDATE — a driver that
        ;; only recognises :data here never resets a peer-opened stream whose
        ;; open frame happened to be the other type, and every DATA that
        ;; stream sends afterward (flags now empty, syn already spent) is then
        ;; silently unroutable rather than politely refused. Measured against
        ;; a real Kubo peer: it opened two such streams toward us — presumably
        ;; its own identify/push — as WINDOW_UPDATE SYNs.
        (and (contains? flags :syn) (not (contains? @(:streams ctx) stream-id)))
        (let [{:keys [session out]} (yamux/reset-stream @(:session ctx) stream-id)]
          (reset! (:session ctx) session)
          (secure-write! ctx out))

        (and (= :data type) (contains? @(:streams ctx) stream-id))
        (swap! (get @(:streams ctx) stream-id) into (:payload frame))

        :else nil)
      true)
    false))

(defn step-until!
  "Poll after the muxer exists: `pred` inspects state `dispatch-one-yamux-frame!`
  mutates (almost always: does one stream's buffer atom hold a complete
  message yet). Each tick, in order: is `pred` satisfied? is there a complete
  Yamux frame already in `plain-buf` to dispatch? is there a complete Noise
  frame in the raw inbox to decrypt into `plain-buf`? — falling back to a
  short wait only when none of the three make progress."
  [ctx pred timeout-ms label]
  (poll-loop! ctx pred
              #(or (dispatch-one-yamux-frame! ctx) (:decrypted (decrypt-one-noise-frame! ctx)))
              timeout-ms label))

;; ── connecting, securing, muxing ─────────────────────────────────────────────

(defn- ed-secret-key
  "Same fallback `libp2p.provider.node/ed-secret-key` uses; duplicated because
  that one is private to its namespace and this driver needs its own identity
  keypair for the handshake payload."
  []
  (let [u (.-utils ed25519)]
    (cond
      (fn? (.-randomSecretKey u)) (.randomSecretKey u)
      (fn? (.-randomPrivateKey u)) (.randomPrivateKey u)
      :else (throw (js/Error. "no ed25519 secret-key generator on this @noble build")))))

(defn connect-and-secure!
  "TCP-connect, run `/noise` + Noise XX (reusing `libp2p.provider.node`'s own
  frame predicates and payload/parsing functions octet-for-octet), and return
  a Promise of a `ctx` whose `send-cs`/`recv-cs` are seeded from the completed
  handshake's split `CipherState`s. Does NOT close the socket — unlike
  `node/dial!`, which is a one-shot measurement."
  [{:keys [host port timeout-ms noise-suite] :or {timeout-ms 25000}}]
  (let [conn (node/connect! host port)
        ctx (session-ctx conn :dialer)
        st noise-suite
        stat (noise/keypair st)]
    (-> (js/Promise.resolve)
        (.then (fn []
                 (node/write! conn (:out (ms/dialer-start (ms/dialer ["/noise"]))))
                 (node/read-until! conn (node/take-ms-message! (:inbox conn)) timeout-ms "ms-header")))
        (.then (fn [_hdr] (node/read-until! conn (node/take-ms-message! (:inbox conn)) timeout-ms "ms-proto")))
        (.then (fn [proto]
                 (when-not (= "/noise" (str/trim proto))
                   (throw (js/Error. (str "peer refused /noise, offered " (pr-str proto)))))
                 (let [ed-sk (ed-secret-key)
                       ed-pub (node/u8->vec (.getPublicKey ed25519 ed-sk))
                       i (noise/initiator {:suite st :s stat :pattern :XX :prologue []})
                       [i m1] (noise/write-message i [])]
                   (node/write-noise! conn m1)
                   (-> (node/read-until! conn (node/take-noise-frame! (:inbox conn)) timeout-ms "noise-msg2")
                       (.then (fn [m2]
                                (let [[i payload] (noise/read-message i m2)
                                      remote (node/parse-remote-payload payload)
                                      [i m3] (noise/write-message
                                              i (node/handshake-payload ed-sk ed-pub (:pub stat)))]
                                  (node/write-noise! conn m3)
                                  (when-not (noise/done? i)
                                    (throw (js/Error. "handshake did not complete")))
                                  (reset! (:send-cs ctx) (:send-cs i))
                                  (reset! (:recv-cs ctx) (:recv-cs i))
                                  (assoc ctx
                                         :remote-identity remote
                                         :handshake-hash (noise/handshake-hash i))))))))))))

(defn negotiate-yamux!
  "Propose `/yamux/1.0.0` over the now-encrypted (but not yet muxed) channel.
  Returns a Promise of `ctx` once accepted. Uses `presecure-step-until!`
  deliberately: nothing here is Yamux-framed yet."
  [ctx timeout-ms]
  (let [{:keys [out]} (ms/dialer-start (ms/dialer [yamux-protocol]))]
    (secure-write! ctx out)
    (-> (presecure-step-until!
         ctx #((node/take-ms-message! (:plain-buf ctx)) @(:plain-buf ctx)) timeout-ms "ms-yamux-header")
        (.then (fn [_hdr]
                 (presecure-step-until!
                  ctx #((node/take-ms-message! (:plain-buf ctx)) @(:plain-buf ctx)) timeout-ms "ms-yamux-proto")))
        (.then (fn [proto]
                 (when-not (= yamux-protocol (str/trim proto))
                   (throw (js/Error. (str "peer refused /yamux/1.0.0, offered " (pr-str proto)))))
                 ctx)))))

;; ── muxed streams ────────────────────────────────────────────────────────────

(defn open-stream!
  "Open a Yamux logical stream and return its numeric id. The stream's
  plaintext buffer is registered before the SYN goes out, so a reply racing
  the write is never lost."
  [ctx]
  (let [{:keys [session stream-id out]} (yamux/open-stream @(:session ctx))]
    (reset! (:session ctx) session)
    (swap! (:streams ctx) assoc stream-id (atom []))
    (secure-write! ctx out)
    stream-id))

(defn negotiate-protocol!
  "Run multistream-select for `protocols` (most-preferred first) on an
  already-open stream. Returns a Promise of the accepted protocol id."
  [ctx stream-id protocols timeout-ms]
  (let [buf (get @(:streams ctx) stream-id)
        {:keys [out dialer]} (ms/dialer-start (ms/dialer protocols))]
    (secure-write! ctx (yamux/data-frame stream-id #{} out))
    (letfn [(recv-loop [d]
              (-> (step-until! ctx #((node/take-ms-message! buf) @buf) timeout-ms
                                (str "ms-substream-" stream-id))
                  (.then (fn [msg]
                           (let [{:keys [dialer out done failed detail]} (ms/dialer-recv d msg)]
                             (when out (secure-write! ctx (yamux/data-frame stream-id #{} out)))
                             (cond
                               done (js/Promise.resolve done)
                               failed (js/Promise.reject
                                       (js/Error. (str "multistream on stream " stream-id ": "
                                                       failed " " detail)))
                               :else (recv-loop dialer)))))))]
      (recv-loop dialer))))

(defn write-length-prefixed!
  "Write OCTETS on STREAM-ID as one varint-length-prefixed message — the
  `msgio` framing identify/kad/bitswap all use for their single protobuf
  message per read (see `kotoba.net.libp2p.dial/identify!` for the reference
  read side this mirrors on the write side)."
  [ctx stream-id octets]
  (secure-write! ctx (yamux/data-frame stream-id #{} (length-prefix octets))))

(defn read-length-prefixed!
  "Promise of the next varint-length-prefixed message on STREAM-ID."
  [ctx stream-id timeout-ms]
  (let [buf (get @(:streams ctx) stream-id)]
    (step-until! ctx #((take-length-prefixed-message! buf) @buf) timeout-ms
                 (str "length-prefixed-" stream-id))))

(defn close-connection! [ctx] (node/close! (:conn ctx)))
