import { useEffect, useRef, useState } from "react";

const SPLASH_FLAG = "edushield.splash.shown";
const MIN_VISIBLE_MS = 4000;
const FADE_OUT_MS = 420;
const MAX_HOLD_MS = 6000;
const AUTO_READY_MS = 4000;
const VIDEO_FALLBACK_MS = 1800;

export function shouldShowStartupSplash(): boolean {
  try {
    return window.sessionStorage.getItem(SPLASH_FLAG) !== "1";
  } catch {
    return true;
  }
}

function markSplashShown(): void {
  try {
    window.sessionStorage.setItem(SPLASH_FLAG, "1");
  } catch {
    /* sessionStorage unavailable */
  }
}

export function StartupSplash({ hold, onDone }: { hold: boolean; onDone: () => void }) {
  const [ready, setReady] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const [minElapsed, setMinElapsed] = useState(false);
  const [forceRelease, setForceRelease] = useState(false);
  const [videoLoaded, setVideoLoaded] = useState(false);
  const [glitching, setGlitching] = useState(false);

  const finishedRef = useRef(false);
  const onDoneRef = useRef(onDone);
  const videoRef = useRef<HTMLVideoElement>(null);
  const splashRef = useRef<HTMLDivElement>(null);
  onDoneRef.current = onDone;

  const finish = (skipHold = false) => {
    if (finishedRef.current) return;
    if (!skipHold && (!minElapsed || hold) && !forceRelease) return;
    finishedRef.current = true;

    setGlitching(true);
    setReady(false);

    window.setTimeout(() => {
      setLeaving(true);
    }, 180);

    window.setTimeout(() => {
      markSplashShown();
      onDoneRef.current();
    }, 180 + FADE_OUT_MS);
  };

  useEffect(() => {
    const minTimer = window.setTimeout(() => setMinElapsed(true), MIN_VISIBLE_MS);
    const maxTimer = window.setTimeout(() => setForceRelease(true), MAX_HOLD_MS);
    const readyTimer = window.setTimeout(() => setReady(true), AUTO_READY_MS);
    const fallbackTimer = window.setTimeout(() => {
      if (!videoRef.current?.readyState) {
        setReady(true);
      }
    }, VIDEO_FALLBACK_MS);

    return () => {
      window.clearTimeout(minTimer);
      window.clearTimeout(maxTimer);
      window.clearTimeout(readyTimer);
      window.clearTimeout(fallbackTimer);
    };
  }, []);

  useEffect(() => {
    if (minElapsed && !hold) {
      finish();
    }
  }, [minElapsed, hold, forceRelease]);

  useEffect(() => {
    const skip = (event: KeyboardEvent) => {
      if (event.key !== "Escape" && event.key !== "Enter" && event.code !== "NumpadEnter" && event.key !== " ") return;
      event.preventDefault();
      finish(true);
    };
    window.addEventListener("keydown", skip);
    return () => window.removeEventListener("keydown", skip);
  }, []);

  const handleVideoLoaded = () => {
    setVideoLoaded(true);
    // autoPlay 属性在部分 WebView 下存在时序差异，这里主动触发播放兜底。
    // 播放被拒绝或解码失败（如 Linux WebKitGTK 缺 H.264 解码器）时回退到 CSS 动画。
    const video = videoRef.current;
    if (video) {
      void video.play().catch(() => {
        setReady(true);
      });
    }
  };

  const handleVideoError = () => {
    setReady(true);
  };

  const handleVideoEnded = () => {
    // 若已进入离开流程（finished），忽略视频结束事件，避免 Enter 提示在
    // glitch/淡出阶段重新闪现。视频正常播完且尚未离开时才显示 Enter。
    if (finishedRef.current) return;
    setReady(true);
  };

  return (
    <div
      ref={splashRef}
      className={`startup-splash ${leaving ? "startup-splash--leaving" : ""}`}
      onClick={() => finish(true)}
      aria-hidden={leaving}
    >
      <video
        ref={videoRef}
        className={`startup-splash__video ${videoLoaded ? "startup-splash__video--loaded" : ""}`}
        muted
        autoPlay
        playsInline
        preload="auto"
        onLoadedData={handleVideoLoaded}
        onError={handleVideoError}
        onEnded={handleVideoEnded}
      >
        <source src="/assets/edushield-intro.webm" type="video/webm" />
        <source src="/assets/edushield-intro-v2-preview.mp4" type="video/mp4" />
      </video>

      <div className={`startup-splash__fallback ${videoLoaded ? "startup-splash__fallback--hidden" : ""}`}>
        <div className="startup-splash__fallback-core">
          <div className="startup-splash__data-ring" />
          <div className="startup-splash__shield" />
        </div>
      </div>

      <div className="startup-splash__pixel-grid" />
      <div className="startup-splash__halftone" />
      <div className="startup-splash__crt-lines" />
      <div className="startup-splash__vignette" />
      <div className="startup-splash__noise" />

      <div className="startup-splash__terminal-header">
        <span>EDUSHIELD</span>
        {" // SECURITY CORE"}
      </div>

      <div className="startup-splash__brand-layer">
        <h1 className={`startup-splash__brand ${glitching ? "startup-splash__brand--glitch" : ""}`}>
          EDUSHIELD
        </h1>
        <div className="startup-splash__status">
          <span className="startup-splash__status-dot" />
          SECURITY CORE ONLINE
        </div>
      </div>

      <div className={`startup-splash__enter-prompt ${ready ? "startup-splash__enter-prompt--visible" : ""}`}>
        <div className="startup-splash__enter-key">PRESS [ ENTER ] TO START</div>
        <div>SECURE · ANALYZE · PROTECT</div>
      </div>

      <div className="startup-splash__skip-hint">ENTER / CLICK TO SKIP INTRO</div>

      <div className="startup-splash__corner startup-splash__corner--tl" />
      <div className="startup-splash__corner startup-splash__corner--tr" />
      <div className="startup-splash__corner startup-splash__corner--bl" />
      <div className="startup-splash__corner startup-splash__corner--br" />
    </div>
  );
}
