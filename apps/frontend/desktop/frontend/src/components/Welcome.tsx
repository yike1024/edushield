import logoWordmark from "../assets/logo-wordmark.svg";
import { useT } from "../lib/i18n";

// Welcome is the empty-state landing: a one-liner, the input affordances
// (/ commands, @ files, Enter), and a few clickable example prompts that send
// immediately so a first turn is one click away.

export function Welcome({ onPrompt, onScenarioPrompt, variant = "default" }: { onPrompt: (text: string) => void; onScenarioPrompt?: (text: string) => void; variant?: "default" | "creation" }) {
  const t = useT();
  if (variant === "creation") {
    const cards = [
      {
        icon: "plan",
        title: t("welcome.creation.explainTitle"),
        body: t("welcome.creation.explainBody"),
      },
      {
        icon: "html",
        title: t("welcome.creation.gitTitle"),
        body: t("welcome.creation.gitBody"),
      },
      {
        icon: "think",
        title: t("welcome.creation.bugTitle"),
        body: t("welcome.creation.bugBody"),
      },
    ];
    return (
      <section className="welcome welcome--creation" aria-label={t("welcome.creation.titlePrimary")}>
        <h2 className="welcome-creation__headline">
          <span>{t("welcome.creation.titlePrimary")}</span>
          <span>{t("welcome.creation.titleSecondary")}</span>
        </h2>
        <div className="welcome-creation__cards" role="list">
          {cards.map((card) => (
            <button
              key={card.title}
              type="button"
              className="welcome-creation__card liquid-button"
              onClick={() => onPrompt(card.title)}
              aria-label={`${card.title}: ${card.body}`}
              role="listitem"
            >
              <span className="welcome-creation__icon" aria-hidden="true">
                {card.icon}
              </span>
              <strong>{card.title}</strong>
              <span>{card.body}</span>
            </button>
          ))}
        </div>
      </section>
    );
  }

  const examples = [t("welcome.ex1"), t("welcome.ex2"), t("welcome.ex3"), t("welcome.ex4")];
  return (
    <section className="welcome welcome--brand" aria-label={t("welcome.title")}>
      <span className="welcome__brand">
        <img src={logoWordmark} className="welcome__brand-logo" alt="EduShield" draggable={false} />
      </span>
      <h2 className="welcome__title">{t("welcome.title")}</h2>
      <div className="welcome__tag">{t("welcome.tagline")}</div>

      <div className="welcome__hints">
        <span>
          <kbd>/</kbd> {t("welcome.hintCommands")}
        </span>
        <span>
          <kbd>@</kbd> {t("welcome.hintFiles")}
        </span>
        <span>
          <kbd>⏎</kbd> {t("welcome.hintSend")}
        </span>
      </div>

      <div className="welcome__scenarios" role="list" aria-label={t("welcome.scenariosLabel")}>
        <button
          type="button"
          className="welcome__scenario liquid-button"
          // 场景卡只预填指令，不直接发送：研判任务需要用户在消息里补 IP/域名（大脑据此建任务）。
          onClick={() => (onScenarioPrompt ?? onPrompt)(t("welcome.phishing.prompt"))}
          aria-label={`${t("welcome.phishing.title")}: ${t("welcome.phishing.hint")}`}
          role="listitem"
        >
          <span className="welcome__scenario-title">{t("welcome.phishing.title")}</span>
          <span className="welcome__scenario-hint">{t("welcome.phishing.hint")}</span>
        </button>
      </div>

      <div className="welcome__examples" role="list" aria-label={t("welcome.examplesLabel")}>
        {examples.map((ex) => (
          <button
            key={ex}
            type="button"
            className="welcome__ex liquid-button"
            // 示例与场景卡一致：只预填，不直接发送，用户可补充后再发送。
            onClick={() => (onScenarioPrompt ?? onPrompt)(ex)}
            aria-label={t("welcome.tryExample", { example: ex })}
            role="listitem"
          >
            {ex}
          </button>
        ))}
      </div>
    </section>
  );
}
