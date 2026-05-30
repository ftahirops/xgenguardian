// trusted-surfaces.js — config loader for surface-shield.js.
//
// MV3 content scripts can't import JSON directly. This file mirrors
// trusted-surfaces.json into a global so surface-shield.js (loaded
// after it in manifest order) can read it via window.XGG_TRUSTED_SURFACES.
//
// KEEP IN SYNC WITH trusted-surfaces.json. When editing, edit the
// JSON file FIRST (it's the source of truth + easy diff target) then
// mirror to this file. A future build step can codegen this.

(function () {
  window.XGG_TRUSTED_SURFACES = {
    surfaces: [
      { host: "chat.openai.com",          selector: '[data-message-author-role="assistant"]',         name: "ChatGPT" },
      { host: "chatgpt.com",              selector: '[data-message-author-role="assistant"]',         name: "ChatGPT" },
      { host: "claude.ai",                selector: ".font-claude-message, .prose",                   name: "Claude" },
      { host: "gemini.google.com",        selector: "model-response, .markdown",                      name: "Gemini" },
      { host: "www.perplexity.ai",        selector: '.prose, [data-testid="answer"]',                 name: "Perplexity" },
      { host: "copilot.microsoft.com",    selector: '.ac-textBlock, [class*="response"]',             name: "Copilot" },
      { host: "mail.google.com",          selector: ".adn .a3s, .ii.gt",                              name: "Gmail" },
      { host: "outlook.live.com",         selector: '.ReadMsgBody, [role="document"]',                name: "Outlook" },
      { host: "outlook.office.com",       selector: '.ReadMsgBody, [role="document"]',                name: "Outlook" },
      { host: "outlook.office365.com",    selector: '.ReadMsgBody, [role="document"]',                name: "Outlook" },
      { host: "app.slack.com",            selector: ".c-message__body, .p-rich_text_section",         name: "Slack" },
      { host: "discord.com",              selector: '[id^="message-content-"]',                       name: "Discord" },
      { host: "teams.microsoft.com",      selector: '.ts-message-content, [class*="messageContent"]', name: "Teams" },
      { host: "www.notion.so",            selector: ".notion-page-content",                           name: "Notion" },
      { host: "notion.so",                selector: ".notion-page-content",                           name: "Notion" },
      { host: "github.com",               selector: ".markdown-body",                                 name: "GitHub" },
      { host: "gitlab.com",               selector: ".md, .description",                              name: "GitLab" },
    ],
  };
})();
