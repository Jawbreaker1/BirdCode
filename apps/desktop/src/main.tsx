import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { docsPreviewBridge } from "./docsPreview";

const docsPreview = import.meta.env.DEV
  ? docsPreviewBridge(new URLSearchParams(window.location.search).get("docs-preview"))
  : undefined;

createRoot(document.getElementById("root")!).render(
  <StrictMode><App bridge={docsPreview} /></StrictMode>,
);
