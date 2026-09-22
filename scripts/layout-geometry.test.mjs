import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { chromium } from "@playwright/test";

const fixturePath = fileURLToPath(new URL("./fixtures/hub-layout.html", import.meta.url));
const cssPath = fileURLToPath(new URL("../apps/hub/src/app/globals.css", import.meta.url));

const VIEWPORTS = [
  [1920, 1080],
  [1440, 900],
  [1280, 720],
  [1024, 768],
  [768, 1024],
  [390, 844],
  [320, 700]
];

const APPEARANCES = [
  { font: "times", scale: "90", radius: "compact", surface: "neutral" },
  { font: "times", scale: "100", radius: "rounded", surface: "neutral" },
  { font: "verdana", scale: "115", radius: "rounded", surface: "paper" },
  { font: "mono", scale: "115", radius: "compact", surface: "neutral" },
  { font: "arial", scale: "100", radius: "rounded", surface: "warm" },
  { font: "garamond", scale: "90", radius: "compact", surface: "paper" }
];

function overlaps(a, b) {
  return a.left < b.right - 1 && a.right > b.left + 1 && a.top < b.bottom - 1 && a.bottom > b.top + 1;
}

test("Hub shell keeps real cards usable across the viewport and appearance matrix", async (t) => {
  const [html, css] = await Promise.all([readFile(fixturePath, "utf8"), readFile(cssPath, "utf8")]);
  const browser = await chromium.launch({ headless: true, executablePath: process.env.BROWSER_EXECUTABLE_PATH || undefined });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.setContent(html);
  await page.addStyleTag({ content: css });

  for (const [width, height] of VIEWPORTS) {
    for (const appearance of APPEARANCES) {
      await page.setViewportSize({ width, height });
      await page.evaluate((nextAppearance) => {
        for (const [key, value] of Object.entries(nextAppearance)) {
          document.documentElement.dataset[key === "scale" ? "fontScale" : key] = value;
        }
      }, appearance);
      await page.evaluate(() => document.fonts?.ready);

      const metrics = await page.evaluate(() => {
        const rect = (selector) => {
          const element = document.querySelector(selector);
          if (!element) return null;
          const box = element.getBoundingClientRect();
          const style = getComputedStyle(element);
          return {
            left: box.left,
            right: box.right,
            top: box.top,
            bottom: box.bottom,
            width: box.width,
            height: box.height,
            display: style.display,
            columns: style.gridTemplateColumns,
            minWidth: style.minWidth
          };
        };
        const rects = (selector) => [...document.querySelectorAll(selector)].map((element) => {
          const box = element.getBoundingClientRect();
          const style = getComputedStyle(element);
          return {
            left: box.left,
            right: box.right,
            top: box.top,
            bottom: box.bottom,
            width: box.width,
            height: box.height,
            text: element.textContent?.trim() ?? "",
            writingMode: style.writingMode,
            whiteSpace: style.whiteSpace,
            fontSize: Number.parseFloat(style.fontSize) || 16
          };
        });
        const sidebar = rect(".os-dock");
        const workspace = rect(".hub-workspace");
        return {
          clientWidth: document.documentElement.clientWidth,
          viewportWidth: window.innerWidth,
          documentWidth: document.documentElement.scrollWidth,
          bodyWidth: document.body.scrollWidth,
          sidebar,
          workspace,
          dashboard: rect(".dashboard-grid"),
          registry: rect(".module-window"),
          quickActions: rect(".quick-actions"),
          singleRegistryGrid: rect(".hub-registry-group:nth-of-type(2) .module-grid"),
          singleRegistryCard: rect(".hub-registry-group:nth-of-type(2) .module-card"),
          dashboardCards: rects(".dashboard-grid > .panel"),
          registryCards: rects(".module-card"),
          navLabels: rects(".dock-nav strong"),
          shellControls: rects(".shell-tools > *"),
          topControls: rects(".top-actions > *"),
          gridColumns: [rect(".dashboard-grid"), rect(".module-grid")].map((item) => item?.columns ?? "")
        };
      });

      const label = `${width}x${height} ${JSON.stringify(appearance)}`;
      assert.ok(metrics.documentWidth <= metrics.viewportWidth + 1, `page overflow: ${label}`);
      assert.ok(metrics.bodyWidth <= metrics.viewportWidth + 1, `body overflow: ${label}`);
      assert.ok(metrics.sidebar && metrics.workspace, `shell rendered: ${label}`);
      assert.ok(metrics.sidebar.width >= 240 && metrics.sidebar.width <= 280 || width < 981, `bounded sidebar: ${label}`);
      assert.ok(metrics.workspace.width >= (width >= 1024 ? 500 : metrics.clientWidth - 2), `usable workspace: ${label}`);
      assert.ok(metrics.workspace.left >= metrics.sidebar.right - 1 || width < 981, `workspace follows dock: ${label}`);
      assert.ok(metrics.dashboardCards.length >= 4 && metrics.registryCards.length >= 7, `representative cards rendered: ${label}`);

      for (const card of [...metrics.dashboardCards, ...metrics.registryCards]) {
        assert.ok(card.width >= 220, `card collapsed below readable width (${Math.round(card.width)}px): ${label}`);
        assert.ok(card.left >= metrics.workspace.left - 1 && card.right <= metrics.workspace.right + 1, `card escaped workspace: ${label}`);
      }
      if (width >= 1024) {
        assert.ok(metrics.quickActions.width >= metrics.workspace.width * 0.45, `quick actions stranded in a narrow column: ${label}`);
        assert.ok(metrics.singleRegistryCard.width >= metrics.singleRegistryGrid.width * 0.8, `single registry card stranded in a narrow column: ${label}`);
      }

      for (const columns of metrics.gridColumns) {
        assert.ok(!/(^|\s)0px(\s|$)/.test(columns), `collapsed implicit grid track: ${columns} (${label})`);
      }

      for (const labelRect of metrics.navLabels) {
        assert.equal(labelRect.writingMode, "horizontal-tb", `vertical nav writing mode: ${label}`);
        assert.equal(labelRect.whiteSpace, "nowrap", `nav label wraps: ${label}`);
        assert.ok(labelRect.width >= 36 && labelRect.height <= labelRect.fontSize * 2.2, `nav label became a character stack: ${label}`);
      }

      for (const control of [...metrics.shellControls, ...metrics.topControls]) {
        assert.ok(control.width >= 36 && control.height >= 32, `primary control collapsed: ${label}`);
      }
      for (const group of [metrics.shellControls, metrics.topControls]) {
        for (let index = 0; index < group.length; index += 1) {
          for (let next = index + 1; next < group.length; next += 1) {
            assert.equal(overlaps(group[index], group[next]), false, `primary controls collide: ${label}`);
          }
        }
      }
    }
  }

  if (process.env.LAYOUT_GEOMETRY_SCREENSHOTS === "1") {
    for (const [width, height] of [[1440, 900], [390, 844], [320, 700]]) {
      await page.setViewportSize({ width, height });
      await page.screenshot({ path: `layout-geometry-${width}.png`, fullPage: true });
    }
  }
});
