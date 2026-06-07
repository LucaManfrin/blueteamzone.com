import { visit } from "unist-util-visit";

/**
 * Transforms GitHub-style admonitions into styled callout blocks:
 *
 *   > [!NOTE]
 *   > Body text...
 *
 * Supported types: NOTE, TIP, WARNING, DANGER, IMPORTANT, CAUTION.
 * Plain blockquotes (no marker) are left untouched and use the default style.
 */
const LABELS = {
  NOTE: { cls: "callout--note", icon: "ℹ", label: "Note" },
  TIP: { cls: "callout--tip", icon: "✓", label: "Tip" },
  IMPORTANT: { cls: "callout--note", icon: "★", label: "Important" },
  WARNING: { cls: "callout--warning", icon: "⚠", label: "Warning" },
  CAUTION: { cls: "callout--warning", icon: "⚠", label: "Caution" },
  DANGER: { cls: "callout--danger", icon: "✗", label: "Danger" },
};

const MARKER = /^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION|DANGER)\]\s*/i;

export function remarkCallouts() {
  return (tree) => {
    visit(tree, "blockquote", (node) => {
      const first = node.children?.[0];
      if (!first || first.type !== "paragraph") return;
      const firstText = first.children?.[0];
      if (!firstText || firstText.type !== "text") return;

      const match = firstText.value.match(MARKER);
      if (!match) return;

      const type = match[1].toUpperCase();
      const meta = LABELS[type];
      if (!meta) return;

      // Strip the marker from the first text node.
      firstText.value = firstText.value.replace(MARKER, "");
      if (firstText.value === "" && first.children.length === 1) {
        node.children.shift();
      }

      // Render as <div class="callout callout--x"> with an icon column.
      node.data = node.data || {};
      node.data.hName = "div";
      node.data.hProperties = {
        className: ["callout", meta.cls],
        role: "note",
        "aria-label": meta.label,
      };

      const iconNode = {
        type: "html",
        value: `<span class="callout__icon" aria-hidden="true">${meta.icon}</span>`,
      };
      const contentWrap = {
        type: "html",
        value: '<div class="callout__content">',
      };
      const contentClose = { type: "html", value: "</div>" };

      node.children = [iconNode, contentWrap, ...node.children, contentClose];
    });
  };
}
