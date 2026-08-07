import { createServer } from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "@playwright/test";
import { Miniflare } from "miniflare";
import { __test as adminTest } from "../src/admin.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKER_ROOT = path.resolve(HERE, "..");
const REPO_ROOT = path.resolve(WORKER_ROOT, "..");
const ARTIFACT_ROOT = path.join(REPO_ROOT, ".local", "browser-ui-gate");
const SCREENSHOT_ROOT = path.join(ARTIFACT_ROOT, "screenshots");

const ADMIN_SESSION_TOKEN = "browser-ui-admin-session";
const PUBLIC_SESSION_TOKEN = "browser-ui-public-session";
const CSRF = "browser-ui-csrf";
const PUBLIC_UUID = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
const CLIENT_IP = "198.51.100.9";
const AES_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const HMAC_KEY = "browser-ui-hmac-test-key-with-at-least-32-bytes";
const TOTP_SECRET = "JBSWY3DPEHPK3PXP";

const VIEWPORTS = [
  { name: "phone-320x568", width: 320, height: 568 },
  { name: "phone-360x800", width: 360, height: 800 },
  { name: "phone-390x844", width: 390, height: 844 },
  { name: "pad-768x1024", width: 768, height: 1024 },
  { name: "laptop-1024x768", width: 1024, height: 768 },
  { name: "laptop-1366x768", width: 1366, height: 768 },
  { name: "desktop-1440x900", width: 1440, height: 900 },
];
const THEMES = ["light", "dark"];
const RESULTS = [];

let miniflare;
let demoServer;
let workerBaseUrl;
let demoBaseUrl;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function makeInvite(index) {
  const suffix = String(index + 1).padStart(12, "0");
  const uuid = index === 0
    ? PUBLIC_UUID
    : `7c484f74-6d93-43d1-9441-${suffix}`;
  const username = index === 0
    ? `longusername${"x".repeat(68)}`
    : `browser-user-${String(index + 1).padStart(2, "0")}`;
  return {
    uuid,
    username,
    name: username,
    email: `${username.slice(0, 40)}@example.test`,
    remark: index === 0 ? "Primary responsive-layout fixture" : `Fixture ${index + 1}`,
    accessKeyHmac: sha256(`browser-ui-access-key-${index}`),
    credentialVersion: 2,
    accessCredentialVersion: 1,
    legacyUuidLoginUntil: "2099-07-01T00:00:00.000Z",
    apiConfigs: index === 0 ? [{
      id: "browser-provider",
      name: "OpenAI compatible",
      baseUrl: "https://provider.example.test/v1",
      apiKey: "sk-browser-ui-test-sentinel",
    }] : [],
    sub2apiSync: index === 0 ? {
      userId: 11,
      tokenId: 21,
      username,
      email: `${username.slice(0, 40)}@example.test`,
      loginUrl: "https://api.example.test/login",
      loginPassword: "browser-ui-login-test-sentinel",
      passwordHashFingerprint: "f".repeat(64),
      syncedAt: "2026-07-21T12:00:00.000Z",
    } : {},
  };
}

function makeRecords() {
  return Array.from({ length: 20 }, (_, index) => ({
    id: `network-${String(index + 1).padStart(2, "0")}`,
    addedAt: "2026-07-20T12:00:00.000Z",
    updatedAt: "2026-07-21T12:00:00.000Z",
    expiresAt: "2099-07-01T00:00:00.000Z",
    country: "Documentation",
    region: "Responsive testing region with a deliberately long label",
    city: "Layout City",
    timezone: "Etc/UTC",
    colo: "TST",
    asn: "AS64500",
    asOrganization: "Browser UI integration fixture",
    geoSource: "test",
    ips: [{
      ip: index === 0 ? CLIENT_IP : `198.51.${100 + index}.9`,
      cidr: index === 0 ? "198.51.100.0/24" : `198.51.${100 + index}.0/24`,
      listValue: index === 0 ? "198.51.100.0/24" : `198.51.${100 + index}.0/24`,
      listItemId: `list-item-${index + 1}`,
    }],
  }));
}

function usageItem(index = 0) {
  return {
    id: 9000 - index,
    requestId: `req_browser_ui_${String(index + 1).padStart(2, "0")}_${"x".repeat(36)}`,
    model: index % 2 ? "gpt-5.6-mini" : "gpt-5.6",
    requestedModel: index % 2 ? "gpt-5.6-mini" : "gpt-5.6-long-model-alias-for-layout-testing",
    inputTokens: 1200 + index,
    outputTokens: 340 + index,
    cacheCreationTokens: 20,
    cacheReadTokens: 80,
    totalCost: "0.012340",
    actualCost: "0.010210",
    durationMs: 830 + index,
    stream: index % 2 === 0,
    requestType: index % 2 ? "responses" : "chat_completions",
    inboundEndpoint: "/v1/responses/with/a/deliberately/long/metadata-only/path",
    createdAt: `2026-07-21T12:${String(index).padStart(2, "0")}:00.000Z`,
  };
}

function syncResponse(request) {
  return request.json().then((body) => {
    if (body.action === "usage_logs_list") {
      return Response.json({
        ok: true,
        action: body.action,
        items: Array.from({ length: 25 }, (_, index) => usageItem(index)),
        query: body.query || "",
        filters: {
          requestId: body.requestId || "",
          model: body.model || "",
          timePreset: body.timePreset || "1h",
          dateFrom: body.dateFrom || "",
          dateTo: body.dateTo || "",
        },
        page: { pageSize: 25, hasMore: true, nextCursor: 8975, nextCursorCreatedAt: "2026-07-21T11:35:00.000Z" },
        modelOptions: ["gpt-5.6", "gpt-5.6-mini"],
        syncedAt: "2026-07-21T12:30:00.000Z",
      });
    }
    if (body.action === "usage_log_detail") {
      const item = usageItem(0);
      return Response.json({ ok: true, action: body.action, item, items: [item] });
    }
    return Response.json({ ok: true, action: body.action });
  });
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return server.address().port;
}

function installVitalsObserver() {
  window.__browserUiVitals = {
    cls: 0,
    lcp: 0,
    events: [],
    eventObserverSupported: false,
  };
  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) window.__browserUiVitals.lcp = entry.startTime;
    }).observe({ type: "largest-contentful-paint", buffered: true });
  } catch {}
  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (!entry.hadRecentInput) window.__browserUiVitals.cls += entry.value;
      }
    }).observe({ type: "layout-shift", buffered: true });
  } catch {}
  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        window.__browserUiVitals.events.push({
          name: entry.name,
          duration: entry.duration,
          interactionId: entry.interactionId || 0,
        });
      }
    }).observe({ type: "event", buffered: true, durationThreshold: 16 });
    window.__browserUiVitals.eventObserverSupported = true;
  } catch {}
}

async function seedWorker() {
  const response = await miniflare.dispatchFetch("https://api.example.test/__test__/seed", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      invites: Array.from({ length: 25 }, (_, index) => makeInvite(index)),
      records: makeRecords(),
      publicUuid: PUBLIC_UUID,
      publicSessionHash: sha256(PUBLIC_SESSION_TOKEN),
      adminSessionHash: sha256(ADMIN_SESSION_TOKEN),
      csrf: CSRF,
    }),
  });
  const responseBody = await response.text();
  expect(response.status, responseBody).toBe(200);
}

async function turnstileRoute(route) {
  await route.fulfill({
    status: 200,
    contentType: "application/javascript; charset=utf-8",
    body: `
      window.turnstile = {
        render(selector, options) {
          const target = document.querySelector(selector);
          target.dataset.renderedSize = options.size;
          const fixture = document.createElement("div");
          fixture.setAttribute("role", "group");
          fixture.setAttribute("aria-label", "Turnstile test fixture");
          fixture.style.cssText = options.size === "compact"
            ? "width:150px;height:140px;max-width:100%;background:#e5e5ea;border:1px solid #8e8e93"
            : "width:100%;height:70px;max-width:100%;background:#e5e5ea;border:1px solid #8e8e93";
          target.replaceChildren(fixture);
          options.callback("browser-ui-turnstile-token");
          return "browser-ui-widget";
        }
      };
      const callbackName = new URL(document.currentScript.src).searchParams.get("onload");
      window[callbackName]?.();
    `,
  });
}

async function controlledTurnstileRoute(route) {
  await route.fulfill({
    status: 200,
    contentType: "application/javascript; charset=utf-8",
    body: `
      window.turnstile = {
        render(selector, options) {
          window.__turnstileOptions = options;
          const target = document.querySelector(selector);
          target.dataset.renderedSize = options.size;
          const fixture = document.createElement("div");
          fixture.setAttribute("role", "group");
          fixture.setAttribute("aria-label", "Turnstile controlled fixture");
          fixture.style.cssText = "width:100%;height:70px;max-width:100%;background:#e5e5ea;border:1px solid #8e8e93";
          target.replaceChildren(fixture);
          return "controlled-widget";
        },
        reset(widgetId) {
          window.__turnstileResetId = widgetId;
        }
      };
      const callbackName = new URL(document.currentScript.src).searchParams.get("onload");
      window[callbackName]?.();
    `,
  });
}

async function pageGeometry(page) {
  return await page.evaluate(() => {
    const viewportWidth = document.documentElement.clientWidth;
    const isVisible = (element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      const closedDetails = element.closest("details:not([open])");
      if (closedDetails && element !== closedDetails.querySelector(":scope > summary")) return false;
      if (typeof element.checkVisibility === "function" && !element.checkVisibility({
        checkOpacity: true,
        checkVisibilityCSS: true,
        contentVisibilityAuto: true,
      })) return false;
      const autoCard = element.closest(".invite-card");
      if (autoCard && autoCard !== element && getComputedStyle(autoCard).contentVisibility === "auto") {
        const cardRect = autoCard.getBoundingClientRect();
        if (cardRect.bottom <= 0 || cardRect.top >= innerHeight) return false;
      }
      return style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
    };
    const hasHorizontalScroller = (element) => {
      for (let current = element.parentElement; current; current = current.parentElement) {
        const overflow = getComputedStyle(current).overflowX;
        if ((overflow === "auto" || overflow === "scroll") && current.scrollWidth > current.clientWidth) return true;
      }
      return false;
    };
    const overflow = [...document.querySelectorAll("body *")]
      .filter(isVisible)
      .filter((element) => !hasHorizontalScroller(element))
      .map((element) => ({ element, rect: element.getBoundingClientRect() }))
      .filter(({ rect }) => rect.left < -1 || rect.right > viewportWidth + 1)
      .map(({ element, rect }) => ({
        tag: element.tagName,
        id: element.id,
        className: String(element.className || "").slice(0, 100),
        left: Math.round(rect.left),
        right: Math.round(rect.right),
        viewportWidth,
      }));

    const controls = [...document.querySelectorAll("button, a, input, textarea, select, summary, [role=tab]")]
      .filter(isVisible)
      .map((element) => ({ element, rect: element.getBoundingClientRect() }))
      .filter(({ rect }) => rect.bottom > 0 && rect.top < innerHeight);
    const overlaps = [];
    for (let leftIndex = 0; leftIndex < controls.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < controls.length; rightIndex += 1) {
        const left = controls[leftIndex];
        const right = controls[rightIndex];
        if (left.element.contains(right.element) || right.element.contains(left.element)) continue;
        const width = Math.min(left.rect.right, right.rect.right) - Math.max(left.rect.left, right.rect.left);
        const height = Math.min(left.rect.bottom, right.rect.bottom) - Math.max(left.rect.top, right.rect.top);
        if (width > 2 && height > 2) {
          overlaps.push({
            left: `${left.element.tagName}.${String(left.element.className || "").slice(0, 50)}`,
            right: `${right.element.tagName}.${String(right.element.className || "").slice(0, 50)}`,
            leftName: String(left.element.getAttribute("name") || ""),
            rightName: String(right.element.getAttribute("name") || ""),
            leftParent: String(left.element.parentElement?.className || "").slice(0, 50),
            rightParent: String(right.element.parentElement?.className || "").slice(0, 50),
            leftForm: String(left.element.closest("form")?.className || "").slice(0, 50),
            rightForm: String(right.element.closest("form")?.className || "").slice(0, 50),
            leftText: String(left.element.textContent || "").trim().slice(0, 60),
            rightText: String(right.element.textContent || "").trim().slice(0, 60),
            leftTop: Math.round(left.rect.top),
            rightTop: Math.round(right.rect.top),
            width: Math.round(width),
            height: Math.round(height),
          });
        }
      }
    }

    const clippedText = [...document.querySelectorAll("h1, h2, h3, button, a, summary, .hint, .muted")]
      .filter(isVisible)
      .filter((element) => {
        const style = getComputedStyle(element);
        if (style.textOverflow === "ellipsis" || hasHorizontalScroller(element)) return false;
        return element.scrollWidth > element.clientWidth + 1;
      })
      .map((element) => ({
        tag: element.tagName,
        text: String(element.textContent || "").trim().slice(0, 80),
        clientWidth: element.clientWidth,
        scrollWidth: element.scrollWidth,
      }));

    const h1Sizes = [...document.querySelectorAll("h1")].filter(isVisible)
      .map((element) => Number.parseFloat(getComputedStyle(element).fontSize));
    const controlSizes = controls.map(({ element }) => Number.parseFloat(getComputedStyle(element).fontSize));
    const parseColor = (value) => {
      const numbers = String(value).match(/[\d.]+/g)?.map(Number) || [];
      return numbers.length >= 3
        ? [numbers[0], numbers[1], numbers[2], numbers.length >= 4 ? numbers[3] : 1]
        : [0, 0, 0, 0];
    };
    const composite = (foreground, background) => {
      const alpha = foreground[3] + (background[3] * (1 - foreground[3]));
      if (alpha <= 0) return [0, 0, 0, 0];
      return [
        ((foreground[0] * foreground[3]) + (background[0] * background[3] * (1 - foreground[3]))) / alpha,
        ((foreground[1] * foreground[3]) + (background[1] * background[3] * (1 - foreground[3]))) / alpha,
        ((foreground[2] * foreground[3]) + (background[2] * background[3] * (1 - foreground[3]))) / alpha,
        alpha,
      ];
    };
    const effectiveBackground = (element) => {
      const layers = [];
      for (let current = element; current; current = current.parentElement) {
        layers.push(parseColor(getComputedStyle(current).backgroundColor));
      }
      let result = [255, 255, 255, 1];
      for (const layer of layers.reverse()) result = composite(layer, result);
      return result;
    };
    const luminance = (color) => {
      const channels = color.slice(0, 3).map((channel) => {
        const value = channel / 255;
        return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      });
      return (0.2126 * channels[0]) + (0.7152 * channels[1]) + (0.0722 * channels[2]);
    };
    const contrastRatio = (foreground, background) => {
      const foregroundLuminance = luminance(composite(foreground, background));
      const backgroundLuminance = luminance(background);
      return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05)
        / (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
    };
    const contrastFailures = [...document.querySelectorAll(
      ".hint, .muted, .empty, .usage-detail dt, small, .lede, .eyebrow, .preview-label, .expiry-field span, .time-grid span, .hero-copy, .panel-subtitle, .footer-note, .field-hint, .helper-note",
    )]
      .filter(isVisible)
      .map((element) => {
        const background = effectiveBackground(element);
        const ratio = contrastRatio(parseColor(getComputedStyle(element).color), background);
        return { element, ratio };
      })
      .filter(({ ratio }) => ratio < 4.5)
      .map(({ element, ratio }) => ({
        tag: element.tagName,
        className: String(element.className || "").slice(0, 100),
        text: String(element.textContent || "").trim().slice(0, 80),
        ratio: Number(ratio.toFixed(2)),
      }));
    return {
      viewportWidth,
      documentScrollWidth: document.documentElement.scrollWidth,
      bodyScrollWidth: document.body.scrollWidth,
      mainTop: document.querySelector("main")?.getBoundingClientRect().top ?? null,
      overflow,
      overlaps,
      clippedText,
      h1Sizes,
      controlSizes,
      contrastFailures,
    };
  });
}

async function screenshotPixels(decoderPage, buffer) {
  return await decoderPage.evaluate(async (source) => {
    const image = new Image();
    image.src = source;
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    context.drawImage(image, 0, 0);
    const stepX = Math.max(1, Math.floor(canvas.width / 80));
    const stepY = Math.max(1, Math.floor(canvas.height / 80));
    const colors = new Set();
    let opaque = 0;
    let minimum = 255;
    let maximum = 0;
    for (let y = 0; y < canvas.height; y += stepY) {
      for (let x = 0; x < canvas.width; x += stepX) {
        const [red, green, blue, alpha] = context.getImageData(x, y, 1, 1).data;
        if (alpha > 0) opaque += 1;
        const luminance = Math.round((red * 0.2126) + (green * 0.7152) + (blue * 0.0722));
        minimum = Math.min(minimum, luminance);
        maximum = Math.max(maximum, luminance);
        colors.add(`${red >> 4}:${green >> 4}:${blue >> 4}:${alpha >> 4}`);
      }
    }
    return { width: canvas.width, height: canvas.height, opaque, colorBuckets: colors.size, luminanceRange: maximum - minimum };
  }, `data:image/png;base64,${buffer.toString("base64")}`);
}

async function collectVitals(page) {
  await page.waitForTimeout(350);
  return await page.evaluate(() => {
    const navigation = performance.getEntriesByType("navigation")[0];
    const firstContentfulPaint = performance.getEntriesByType("paint")
      .find((entry) => entry.name === "first-contentful-paint");
    const values = window.__browserUiVitals || {};
    const eventDurations = (values.events || []).map((entry) => entry.duration);
    return {
      playwrightObservedLcpMs: values.lcp ? Number(values.lcp) : null,
      playwrightObservedCls: Number(values.cls || 0),
      firstContentfulPaintMs: firstContentfulPaint ? Number(firstContentfulPaint.startTime) : null,
      navigationDurationMs: Number(navigation?.duration || 0),
      domContentLoadedMs: Number(navigation?.domContentLoadedEventEnd || 0),
      eventObserverSupported: Boolean(values.eventObserverSupported),
      observedEventCount: eventDurations.length,
      maxObservedEventDurationMs: eventDurations.length ? Math.max(...eventDurations) : null,
      eventTimingUpperBoundMs: eventDurations.length ? Math.max(...eventDurations) : 16,
      observedEvents: (values.events || []).slice(-16).map((entry) => ({
        name: String(entry.name || "").slice(0, 32),
        duration: Number(entry.duration || 0),
        interactionId: Number(entry.interactionId || 0),
      })),
    };
  });
}

async function exerciseInteraction(page, scenario) {
  if (scenario === "public-form") {
    await page.locator(".toggle-secret").click();
    await expect(page.locator("#invite_key")).toHaveAttribute("type", "text");
  } else if (scenario === "demo") {
    await page.locator("#goAdmin").click();
    const usersTab = page.locator("#tab-users-button");
    const addTab = page.locator("#tab-add-button");
    await expect(usersTab).toBeVisible();
    await expect(page.locator('[role="tablist"]')).toHaveCount(1);
    await expect(usersTab).toHaveAttribute("aria-controls", "tab-users");
    await expect(addTab).toHaveAttribute("aria-controls", "tab-add");
    await expect(page.locator("#tab-users")).toHaveAttribute("aria-labelledby", "tab-users-button");
    await expect(page.locator("#tab-add")).toHaveAttribute("aria-labelledby", "tab-add-button");
    await page.evaluate(() => document.activeElement?.blur());
    for (let index = 0; index < 20; index += 1) {
      if (await usersTab.evaluate((element) => element === document.activeElement)) break;
      await page.keyboard.press("Tab");
    }
    await expect(usersTab).toBeFocused();
    const focusOutline = await usersTab.evaluate((element) => ({
      style: getComputedStyle(element).outlineStyle,
      width: Number.parseFloat(getComputedStyle(element).outlineWidth),
    }));
    expect(focusOutline.style).not.toBe("none");
    expect(focusOutline.width).toBeGreaterThanOrEqual(2);
    await page.keyboard.press("ArrowRight");
    await expect(addTab).toBeFocused();
    await expect(addTab).toHaveAttribute("aria-selected", "true");
    await expect(page.locator("#tab-add")).toBeVisible();
    await page.keyboard.press("Home");
    await expect(usersTab).toBeFocused();
    await expect(usersTab).toHaveAttribute("aria-selected", "true");
    await page.evaluate(() => window.scrollTo(0, 0));
  } else if (scenario === "usage-list") {
    const search = page.locator('input[name="q"]');
    await search.fill("req_browser_ui");
    await expect(search).toHaveValue("req_browser_ui");
  } else if (scenario === "admin-detail") {
    await page.locator(".ip-group[open]").scrollIntoViewIfNeeded();
  }
  await page.waitForTimeout(100);
}

async function validateTurnstile(page, expectedSize) {
  const widget = page.locator("#turnstile-widget");
  await expect(widget).toHaveAttribute("data-rendered-size", expectedSize);
  const bounds = await widget.boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds.x).toBeGreaterThanOrEqual(0);
  expect(bounds.x + bounds.width).toBeLessThanOrEqual((await page.evaluate(() => innerWidth)) + 1);
}

async function validateDarkBrandIcon(page, decoderPage) {
  const icon = page.locator(".sub2api-icon").first();
  await expect(icon).toBeVisible();
  const state = await icon.evaluate((element) => {
    const image = element.querySelector("img");
    return {
      backgroundColor: getComputedStyle(element).backgroundColor,
      imageComplete: Boolean(image?.complete),
      imageNaturalWidth: Number(image?.naturalWidth || 0),
    };
  });
  expect(state.backgroundColor).toBe("rgb(245, 245, 247)");
  expect(state.imageComplete).toBe(true);
  expect(state.imageNaturalWidth).toBeGreaterThan(0);
  const pixels = await screenshotPixels(decoderPage, await icon.screenshot());
  expect(pixels.colorBuckets).toBeGreaterThan(4);
  expect(pixels.luminanceRange).toBeGreaterThan(100);
  return { ...state, pixels };
}

function cssColorContrast(foreground, background) {
  const luminance = (value) => {
    const channels = String(value).match(/[\d.]+/g)?.slice(0, 3).map(Number) || [];
    if (channels.length !== 3) return 0;
    const linear = channels.map((channel) => {
      const normalized = channel / 255;
      return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
    });
    return (0.2126 * linear[0]) + (0.7152 * linear[1]) + (0.0722 * linear[2]);
  };
  const values = [luminance(foreground), luminance(background)].sort((left, right) => right - left);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

async function validateDarkDemoBrandIcon(page, decoderPage) {
  const icon = page.locator(".brand-mark").first();
  await expect(icon).toBeVisible();
  const state = await icon.evaluate((element) => {
    const svg = element.querySelector("svg");
    const svgPath = svg?.querySelector("path");
    const svgBounds = svg?.getBoundingClientRect();
    const pathBounds = svgPath?.getBoundingClientRect();
    return {
      backgroundColor: getComputedStyle(element).backgroundColor,
      svgPathCount: element.querySelectorAll("svg path").length,
      svgBounds: svgBounds ? { width: svgBounds.width, height: svgBounds.height } : null,
      pathBounds: pathBounds ? { width: pathBounds.width, height: pathBounds.height } : null,
      pathFill: svgPath ? getComputedStyle(svgPath).fill : "",
      pathOpacity: svgPath ? getComputedStyle(svgPath).opacity : "",
      pathVisibility: svgPath ? getComputedStyle(svgPath).visibility : "",
    };
  });
  expect(state.backgroundColor).toBe("rgb(245, 245, 247)");
  expect(state.svgPathCount).toBeGreaterThan(0);
  expect(state.svgBounds?.width).toBeGreaterThan(30);
  expect(state.svgBounds?.height).toBeGreaterThan(30);
  expect(state.pathBounds?.width).toBeGreaterThan(30);
  expect(state.pathBounds?.height).toBeGreaterThan(30);
  expect(state.pathOpacity).toBe("1");
  expect(state.pathVisibility).toBe("visible");
  expect(cssColorContrast(state.pathFill, state.backgroundColor)).toBeGreaterThanOrEqual(4.5);
  const screenshotPath = path.join(SCREENSHOT_ROOT, "demo-brand-icon-phone-320x568-dark.png");
  const screenshot = await icon.screenshot({ path: screenshotPath });
  const pixels = await screenshotPixels(decoderPage, screenshot);
  expect(pixels.colorBuckets).toBeGreaterThan(4);
  expect(pixels.luminanceRange).toBeGreaterThan(100);
  return { ...state, pixels, screenshot: path.relative(REPO_ROOT, screenshotPath) };
}

async function captureScenario(page, decoderPage, viewport, theme, scenario, url) {
  await page.bringToFront();
  const requests = [];
  const consoleErrors = [];
  const pageErrors = [];
  const onRequest = (request) => requests.push(request.url());
  const onConsole = (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  };
  const onPageError = (error) => pageErrors.push(String(error.message || error));
  page.on("request", onRequest);
  page.on("console", onConsole);
  page.on("pageerror", onPageError);
  const response = await page.goto(url, { waitUntil: "networkidle" });
  expect(response?.status()).toBeLessThan(400);
  await expect(page.locator("main")).toBeVisible();
  const htmlBytes = Buffer.byteLength(await page.content(), "utf8");
  if (scenario === "admin-list") expect(htmlBytes).toBeLessThanOrEqual(96 * 1024);
  if (["admin-detail", "admin-create", "admin-maintenance"].includes(scenario)) {
    expect(htmlBytes).toBeLessThanOrEqual(128 * 1024);
  }

  if (scenario === "public-form") {
    await validateTurnstile(page, viewport.width < 372 ? "compact" : "flexible");
    if (viewport.width === 320 && viewport.height === 568) {
      const primaryActionBounds = await page.locator("#submit-button").boundingBox();
      expect(primaryActionBounds).not.toBeNull();
      expect(primaryActionBounds.y).toBeLessThan(viewport.height);
    }
  }
  if (scenario === "public-dashboard") {
    await expect(page.getByText("Current network authorization is active", { exact: false })).toBeVisible();
    expect(requests.some((value) => value.startsWith("https://challenges.cloudflare.com/"))).toBe(false);
  }
  if (scenario === "admin-list") {
    await expect(page.locator('.admin-tabs [aria-current="page"]')).toHaveText("UUIDs");
    await expect(page.locator(".invite-list")).toBeVisible();
    await expect(page.locator(".selected-invite-detail, .create-panel, .trash-list")).toHaveCount(0);
  }
  if (scenario === "admin-create") {
    await expect(page.locator('.admin-tabs [aria-current="page"]')).toHaveText("Create");
    await expect(page.locator('form.create input[name="username"]')).toBeVisible();
    await expect(page.locator(".invite-list, .selected-invite-detail, .trash-list")).toHaveCount(0);
  }
  if (scenario === "admin-maintenance") {
    await expect(page.locator('.admin-tabs [aria-current="page"]')).toHaveText("Maintenance");
    await expect(page.getByRole("heading", { name: "Access key migration" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Recycle Bin" })).toBeVisible();
    await expect(page.locator(".invite-list, .selected-invite-detail, form.create")).toHaveCount(0);
  }
  if (scenario === "admin-detail") {
    await expect(page.locator(".selected-invite-detail")).toBeVisible();
    await expect(page.locator(".invite-list, .create-panel, .trash-list")).toHaveCount(0);
    if (viewport.width === 240) {
      const detailPosition = await page.evaluate(() => {
        const tabs = document.querySelector(".admin-tabs")?.getBoundingClientRect();
        const detail = document.querySelector(".selected-invite-detail")?.getBoundingClientRect();
        return {
          tabsBottom: tabs?.bottom ?? null,
          detailTop: detail?.top ?? null,
          scrollY,
        };
      });
      expect(detailPosition.scrollY).toBe(0);
      expect(detailPosition.tabsBottom).not.toBeNull();
      expect(detailPosition.detailTop).not.toBeNull();
      expect(detailPosition.detailTop - detailPosition.tabsBottom).toBeLessThanOrEqual(32);
      expect(detailPosition.detailTop).toBeLessThan(800);
    }
  }
  if (scenario === "usage-list" && viewport.width <= 680) {
    const columns = await page.locator(".usage-row").first().evaluate((element) => getComputedStyle(element).gridTemplateColumns);
    expect(columns.trim().split(/\s+/)).toHaveLength(1);
  }
  if (scenario === "usage-detail" && viewport.width <= 680) {
    const columns = await page.locator(".usage-detail").evaluate((element) => getComputedStyle(element).gridTemplateColumns);
    expect(columns.trim().split(/\s+/)).toHaveLength(1);
  }
  let brandIcon = null;
  if (theme === "dark" && viewport.width === 320) {
    if (scenario === "public-form" || scenario === "admin-list") {
      brandIcon = await validateDarkBrandIcon(page, decoderPage);
    } else if (scenario === "demo") {
      brandIcon = await validateDarkDemoBrandIcon(page, decoderPage);
    }
  }

  await page.waitForTimeout(100);
  await exerciseInteraction(page, scenario);
  const vitals = await collectVitals(page);
  await page.evaluate(() => {
    document.querySelectorAll(".invite-card").forEach((element) => {
      element.style.contentVisibility = "visible";
    });
  });
  if (scenario === "admin-detail") {
    await page.locator(".ip-group[open]").scrollIntoViewIfNeeded();
  }
  const geometry = await pageGeometry(page);
  const geometryDetails = JSON.stringify(geometry, null, 2);
  expect(geometry.documentScrollWidth, geometryDetails).toBeLessThanOrEqual(geometry.viewportWidth + 1);
  expect(geometry.bodyScrollWidth, geometryDetails).toBeLessThanOrEqual(geometry.viewportWidth + 1);
  expect(geometry.overflow, geometryDetails).toEqual([]);
  expect(geometry.overlaps, geometryDetails).toEqual([]);
  expect(geometry.clippedText, geometryDetails).toEqual([]);
  expect(geometry.contrastFailures, geometryDetails).toEqual([]);
  const minimumH1Size = scenario === "public-dashboard" && viewport.width <= 560 ? 24 : 28;
  for (const size of geometry.h1Sizes) expect(size).toBeGreaterThanOrEqual(minimumH1Size);
  for (const size of geometry.h1Sizes) expect(size).toBeLessThanOrEqual(42);
  if (viewport.width <= 680) {
    for (const size of geometry.h1Sizes) expect(size).toBeLessThanOrEqual(32);
  }
  if (scenario === "public-dashboard" && viewport.width <= 560) {
    for (const size of geometry.h1Sizes) expect(size).toBeLessThanOrEqual(24);
  }
  if (scenario === "usage-detail" && viewport.width >= 768) {
    expect(geometry.mainTop, geometryDetails).not.toBeNull();
    expect(geometry.mainTop, geometryDetails).toBeLessThanOrEqual(64);
  }
  for (const size of geometry.controlSizes) expect(size).toBeGreaterThanOrEqual(13);
  for (const size of geometry.controlSizes) expect(size).toBeLessThanOrEqual(17);

  if (vitals.playwrightObservedLcpMs !== null) {
    expect(vitals.playwrightObservedLcpMs).toBeLessThan(2500);
  }
  expect(vitals.playwrightObservedCls).toBeLessThan(0.1);
  expect(vitals.firstContentfulPaintMs).not.toBeNull();
  expect(
    vitals.eventTimingUpperBoundMs,
    JSON.stringify({ scenario, observedEvents: vitals.observedEvents }, null, 2),
  ).toBeLessThan(200);
  expect(pageErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);

  const name = `${scenario}-${viewport.name}-${theme}.png`;
  const screenshotPath = path.join(SCREENSHOT_ROOT, name);
  const screenshot = await page.screenshot({ path: screenshotPath, fullPage: false });
  const pixels = await screenshotPixels(decoderPage, screenshot);
  expect(pixels.opaque).toBeGreaterThan(100);
  expect(pixels.colorBuckets).toBeGreaterThan(4);
  expect(pixels.luminanceRange).toBeGreaterThan(20);

  const browserExternalRequests = requests.filter((value) => (
    !value.startsWith(workerBaseUrl)
    && !value.startsWith(demoBaseUrl)
    && !value.startsWith("data:")
  ));
  if (scenario === "public-form") {
    expect(browserExternalRequests).toHaveLength(1);
    expect(browserExternalRequests[0]).toMatch(/^https:\/\/challenges\.cloudflare\.com\//);
  } else {
    expect(browserExternalRequests).toEqual([]);
  }

  RESULTS.push({
    scenario,
    viewport,
    theme,
    url: new URL(url).pathname,
    geometry,
    vitals,
    pixels,
    requestCount: requests.length,
    htmlBytes,
    brandIcon,
    externalRequests: browserExternalRequests,
    screenshot: path.relative(REPO_ROOT, screenshotPath),
  });
  page.off("request", onRequest);
  page.off("console", onConsole);
  page.off("pageerror", onPageError);
}

test.beforeAll(async () => {
  await mkdir(SCREENSHOT_ROOT, { recursive: true });
  miniflare = new Miniflare({
    modules: true,
    scriptPath: path.join(WORKER_ROOT, "test-support", "browser-ui-harness.js"),
    modulesRoot: WORKER_ROOT,
    modulesRules: [{ type: "ESModule", include: ["**/*.js"] }],
    compatibilityDate: "2026-07-21",
    compatibilityFlags: ["nodejs_compat"],
    host: "127.0.0.1",
    port: 0,
    https: true,
    bindings: {
      ADMIN_USERNAME: "admin",
      ADMIN_PASSWORD_PBKDF2: "pbkdf2_sha256$310000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ADMIN_TOTP_SECRET: TOTP_SECRET,
      CREDENTIAL_ENCRYPTION_KEY: AES_KEY,
      INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
      ALLOWED_HOSTNAMES: "api.example.test,sync.example.test",
      PROVIDER_ALLOWED_HOSTNAMES: "provider.example.test",
      ACCOUNT_ID: "a".repeat(32),
      IP_LIST_ID: "b".repeat(32),
      CLOUDFLARE_API_TOKEN: "browser-ui-cloudflare-test-sentinel",
      TURNSTILE_SITE_KEY: "browser-ui-turnstile-site-key",
      TURNSTILE_SECRET_KEY: "browser-ui-turnstile-secret-sentinel",
      SUB2API_SYNC_SECRET: "s".repeat(32),
      SUB2API_SYNC_URL: "https://sync.example.test/_sub2api-sync/provision",
      SUB2API_DEFAULT_BASE_URL: "https://api.example.test/v1",
      SUB2API_LOGIN_URL: "https://api.example.test/login",
      GEOIP_LOOKUP_URL: "",
      GEOIP_ALLOWED_HOSTNAMES: "",
    },
    kvNamespaces: ["INVITE_STORE"],
    durableObjects: {
      AUTH_RATE_LIMITER: { className: "AuthRateLimiter", useSQLite: true },
      AUTH_STATE: { className: "AuthState", useSQLite: true },
    },
    outboundService: syncResponse,
  });
  const ready = await miniflare.ready;
  workerBaseUrl = `https://api.example.test:${ready.port}`;
  await seedWorker();

  const demoHtml = await readFile(path.join(REPO_ROOT, "demo", "index.html"));
  demoServer = createServer((request, response) => {
    if (request.url === "/demo/" || request.url === "/demo/index.html") {
      response.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      });
      response.end(demoHtml);
      return;
    }
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("Not found");
  });
  const demoPort = await listen(demoServer);
  demoBaseUrl = `http://127.0.0.1:${demoPort}`;
});

test.afterAll(async () => {
  await miniflare?.dispose();
  if (demoServer) await new Promise((resolve) => demoServer.close(resolve));
  const packageJson = JSON.parse(await readFile(path.join(WORKER_ROOT, "package.json"), "utf8"));
  await writeFile(path.join(ARTIFACT_ROOT, "metrics.json"), `${JSON.stringify({
    generatedAt: new Date().toISOString(),
    localOnly: true,
    chromeDevtoolsMcpAvailable: false,
    coreWebVitalsFinalAcceptance: false,
    note: "Playwright lab observations are supplemental. Event Timing is not field INP.",
    playwrightVersion: packageJson.devDependencies["@playwright/test"],
    results: RESULTS,
  }, null, 2)}\n`);
});

test("public Turnstile load failure is visible and retryable without shifting the form", async ({ page, context }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await context.setExtraHTTPHeaders({ "CF-Connecting-IP": CLIENT_IP });
  let scriptAttempts = 0;
  await page.route("https://challenges.cloudflare.com/**", async (route) => {
    scriptAttempts += 1;
    if (scriptAttempts === 1) {
      await route.abort("failed");
      return;
    }
    await turnstileRoute(route);
  });

  await page.goto(`${workerBaseUrl}/allow-ip`, { waitUntil: "domcontentloaded" });
  const control = page.locator("#turnstile-control");
  await expect(control).toHaveAttribute("data-state", "error");
  await expect(page.locator("#turnstile-status")).toHaveAttribute("role", "alert");
  await expect(page.locator("#turnstile-status")).toContainText("Verification could not load");
  await expect(page.locator("#turnstile-retry")).toBeVisible();
  await expect(page.locator("#submit-button")).toBeDisabled();
  const failedBounds = await control.boundingBox();

  await page.locator("#turnstile-retry").click();
  await expect(control).toHaveAttribute("data-state", "verified");
  await expect(page.locator("#turnstile-status")).toHaveAttribute("role", "status");
  await expect(page.locator("#turnstile-status")).toContainText("Verification complete");
  await expect(page.locator("#submit-button")).toBeEnabled();
  const verifiedBounds = await control.boundingBox();

  expect(scriptAttempts).toBe(2);
  expect(failedBounds).not.toBeNull();
  expect(verifiedBounds).not.toBeNull();
  expect(Math.abs(verifiedBounds.height - failedBounds.height)).toBeLessThanOrEqual(1);
});

test("public Turnstile exposes a stable loading state while the client is delayed", async ({ page, context }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await context.setExtraHTTPHeaders({ "CF-Connecting-IP": CLIENT_IP });
  let releaseScript;
  let markScriptRequested;
  const scriptGate = new Promise((resolve) => { releaseScript = resolve; });
  const scriptRequested = new Promise((resolve) => { markScriptRequested = resolve; });
  await page.route("https://challenges.cloudflare.com/**", async (route) => {
    markScriptRequested();
    await scriptGate;
    await controlledTurnstileRoute(route);
  });

  await page.goto(`${workerBaseUrl}/allow-ip`, { waitUntil: "commit" });
  await scriptRequested;
  const control = page.locator("#turnstile-control");
  await expect(control).toHaveAttribute("data-state", "loading");
  await expect(control).toHaveAttribute("aria-busy", "true");
  await expect(page.locator("#turnstile-status")).toHaveText("Loading verification...");
  await expect(page.locator("#submit-button")).toBeDisabled();
  const loadingBounds = await control.boundingBox();

  releaseScript();
  await expect(control).toHaveAttribute("data-state", "ready");
  const readyBounds = await control.boundingBox();
  expect(loadingBounds).not.toBeNull();
  expect(readyBounds).not.toBeNull();
  expect(Math.abs(readyBounds.height - loadingBounds.height)).toBeLessThanOrEqual(1);
});

test("public Turnstile load watchdog exposes recovery after eight seconds", async ({ page, context }) => {
  await page.clock.install();
  await context.setExtraHTTPHeaders({ "CF-Connecting-IP": CLIENT_IP });
  let releaseScript;
  let markScriptRequested;
  const scriptGate = new Promise((resolve) => { releaseScript = resolve; });
  const scriptRequested = new Promise((resolve) => { markScriptRequested = resolve; });
  await page.route("https://challenges.cloudflare.com/**", async (route) => {
    markScriptRequested();
    await scriptGate;
    await controlledTurnstileRoute(route);
  });

  await page.goto(`${workerBaseUrl}/allow-ip`, { waitUntil: "commit" });
  await scriptRequested;
  await expect(page.locator("#turnstile-control")).toHaveAttribute("data-state", "loading");
  await page.clock.fastForward(8001);
  await expect(page.locator("#turnstile-control")).toHaveAttribute("data-state", "error");
  await expect(page.locator("#turnstile-status")).toContainText("taking too long to load");
  await expect(page.locator("#turnstile-retry")).toBeVisible();
  await expect(page.locator("#submit-button")).toBeDisabled();
  releaseScript();
});

test("public Turnstile ignores a stale load callback after watchdog retry succeeds", async ({ page, context }) => {
  await page.clock.install();
  await context.setExtraHTTPHeaders({ "CF-Connecting-IP": CLIENT_IP });
  let scriptAttempts = 0;
  let retryScriptUrl = "";
  await page.route("https://challenges.cloudflare.com/**", async (route) => {
    scriptAttempts += 1;
    if (scriptAttempts === 1) {
      await route.fulfill({
        status: 200,
        contentType: "application/javascript; charset=utf-8",
        body: `window.setTimeout(() => window.onTurnstileLoad?.(), 9000);`,
      });
      return;
    }
    retryScriptUrl = route.request().url();
    await route.fulfill({
      status: 200,
      contentType: "application/javascript; charset=utf-8",
      body: `
        window.__turnstileRenderCount = 0;
        window.turnstile = {
          render(selector, options) {
            window.__turnstileRenderCount += 1;
            if (window.__turnstileRenderCount > 1) throw new Error("duplicate Turnstile render");
            options.callback("watchdog-retry-token");
            return "watchdog-retry-widget";
          },
          reset() {}
        };
        const callbackName = new URL(document.currentScript.src).searchParams.get("onload");
        window[callbackName]?.();
      `,
    });
  });

  await page.goto(`${workerBaseUrl}/allow-ip`, { waitUntil: "domcontentloaded" });
  const control = page.locator("#turnstile-control");
  await page.clock.fastForward(8001);
  await expect(control).toHaveAttribute("data-state", "error");

  await page.locator("#turnstile-retry").click();
  await expect(control).toHaveAttribute("data-state", "verified");
  await expect(page.locator("#submit-button")).toBeEnabled();
  expect(scriptAttempts).toBe(2);
  const retryUrl = new URL(retryScriptUrl);
  expect(retryUrl.searchParams.getAll("onload")).toEqual(["onTurnstileLoadAttempt2"]);

  await page.clock.fastForward(1000);
  await expect(control).toHaveAttribute("data-state", "verified");
  await expect(page.locator("#turnstile-status")).toContainText("Verification complete");
  await expect(page.locator("#submit-button")).toBeEnabled();
  expect(await page.evaluate(() => window.__turnstileRenderCount)).toBe(1);
});

test("public Turnstile lifecycle gates tokens, retries, and duplicate submissions", async ({ page, context }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await context.setExtraHTTPHeaders({ "CF-Connecting-IP": CLIENT_IP });
  await page.route("https://challenges.cloudflare.com/**", controlledTurnstileRoute);
  await page.goto(`${workerBaseUrl}/allow-ip`, { waitUntil: "networkidle" });

  const control = page.locator("#turnstile-control");
  const status = page.locator("#turnstile-status");
  const retry = page.locator("#turnstile-retry");
  const submit = page.locator("#submit-button");
  await expect(control).toHaveAttribute("data-state", "ready");
  await expect(status).toContainText("Complete the verification challenge");
  await expect(submit).toBeDisabled();

  await page.evaluate(() => {
    const token = document.createElement("input");
    token.type = "hidden";
    token.name = "cf-turnstile-response";
    token.value = "controlled-token";
    document.getElementById("allow-network-form")?.appendChild(token);
    window.__turnstileOptions.callback("controlled-token");
  });
  await expect(control).toHaveAttribute("data-state", "verified");
  await expect(submit).toBeEnabled();

  await page.evaluate(() => window.__turnstileOptions["expired-callback"]());
  await expect(control).toHaveAttribute("data-state", "expired");
  await expect(status).toHaveAttribute("role", "alert");
  await expect(status).toContainText("Verification expired");
  await expect(submit).toBeDisabled();
  await expect(page.locator('[name="cf-turnstile-response"]')).toHaveValue("");
  await expect(retry).toBeVisible();

  await retry.click();
  await expect(control).toHaveAttribute("data-state", "ready");
  expect(await page.evaluate(() => window.__turnstileResetId)).toBe("controlled-widget");

  await page.evaluate(() => window.__turnstileOptions["timeout-callback"]());
  await expect(status).toContainText("Verification timed out");
  await expect(control).toHaveAttribute("data-state", "error");
  await retry.click();
  await expect(control).toHaveAttribute("data-state", "ready");

  await page.evaluate(() => window.__turnstileOptions["error-callback"]());
  await expect(status).toContainText("Verification encountered an error");
  await expect(control).toHaveAttribute("data-state", "error");
  await retry.click();
  await page.evaluate(() => window.__turnstileOptions.callback("replacement-token"));

  await page.locator("#invite_key").fill("test-access-key");
  await page.evaluate(() => {
    document.getElementById("allow-network-form")?.addEventListener("submit", (event) => {
      window.__submissionDefaultPrevented = [
        ...(window.__submissionDefaultPrevented || []),
        event.defaultPrevented,
      ];
      event.preventDefault();
    });
  });
  await submit.click();
  await expect(control).toHaveAttribute("data-state", "submitting");
  await expect(status).toContainText("Authorization request in progress");
  await expect(submit).toBeDisabled();
  await expect(submit).toHaveText("Authorizing...");
  await page.evaluate(() => document.getElementById("allow-network-form")?.requestSubmit());
  expect(await page.evaluate(() => window.__submissionDefaultPrevented)).toEqual([false, true]);
});

test("public error pages announce and focus the error heading", async ({ page, context }) => {
  await context.setExtraHTTPHeaders({ "CF-Connecting-IP": CLIENT_IP });
  await page.route("https://challenges.cloudflare.com/**", turnstileRoute);
  await page.goto(`${workerBaseUrl}/allow-ip`, { waitUntil: "networkidle" });

  await Promise.all([
    page.waitForNavigation({ waitUntil: "domcontentloaded" }),
    page.evaluate(() => {
      const form = document.createElement("form");
      form.method = "post";
      form.action = "/allow-ip";
      form.enctype = "text/plain";
      const field = document.createElement("input");
      field.name = "unsupported";
      field.value = "value";
      form.appendChild(field);
      document.body.appendChild(form);
      form.submit();
    }),
  ]);

  await expect(page.locator(".message")).toHaveAttribute("role", "alert");
  await expect(page.locator("#message-title")).toHaveText("Unsupported form format");
  await expect(page.locator("#message-title")).toBeFocused();
});

test("dashboard reports clipboard rejection without an unhandled page error", async ({ page, context }) => {
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async () => { throw new Error("clipboard denied by test"); },
      },
    });
  });
  await context.setExtraHTTPHeaders({ "CF-Connecting-IP": CLIENT_IP });
  await context.addCookies([{
    name: "sub2api_allow_uuid",
    value: PUBLIC_SESSION_TOKEN,
    domain: "api.example.test",
    path: "/allow-ip",
    httpOnly: true,
    secure: false,
    sameSite: "Strict",
  }]);
  await page.goto(`${workerBaseUrl}/allow-ip`, { waitUntil: "networkidle" });

  const copyButton = page.locator(".copy-value").first();
  await copyButton.click();
  await expect(copyButton).toHaveText("Copy failed");
  await expect(page.locator("#copy-status")).toHaveAttribute("role", "alert");
  await expect(page.locator("#copy-status")).toContainText("Select the value and copy it manually");
  expect(pageErrors).toEqual([]);
});

test("admin copy actions report clipboard rejection without unhandled errors", async ({ page, context }) => {
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async () => { throw new Error("admin clipboard denied by test"); },
      },
    });
  });
  await context.addCookies([{
    name: "sub2api_allow_admin",
    value: ADMIN_SESSION_TOKEN,
    domain: "api.example.test",
    path: "/allow-ip/admin",
    httpOnly: true,
    secure: false,
    sameSite: "Strict",
  }]);

  await page.goto(`${workerBaseUrl}/allow-ip/admin?view=create`, { waitUntil: "networkidle" });
  const clipboardStatus = page.locator("#clipboard-status");
  const copyUuid = page.locator("#copy-uuid");
  await copyUuid.click();
  await expect(copyUuid).toHaveText("Copy failed");
  await expect(clipboardStatus).toHaveAttribute("role", "alert");

  await page.locator(".generate-key").click();
  const copyApiKey = page.locator(".copy-api-key:not([disabled])").last();
  await copyApiKey.click();
  await expect(copyApiKey).toHaveText("Copy failed");
  await expect(clipboardStatus).toContainText("Copy failed");

  const editResponse = await page.goto(
    `${workerBaseUrl}/allow-ip/admin?edit=${PUBLIC_UUID}`,
    { waitUntil: "networkidle" },
  );
  expect(editResponse?.status(), await page.locator("body").innerText()).toBe(200);
  await expect(page.locator('input[name="admin_context"][value$="v=e"]')).not.toHaveCount(0);
  const copyRow = page.locator(".copy-row").first();
  await copyRow.click();
  await expect(copyRow).toHaveText("Copy failed");

  const stepUpToken = await adminTest.totp(
    TOTP_SECRET,
    Math.floor(Date.now() / 1000 / 30),
  );
  const rotateForm = page.locator('form:has(input[name="action"][value="rotate_access_key"])');
  await rotateForm.locator('input[name="step_up_token"]').fill(stepUpToken);
  await Promise.all([
    page.waitForNavigation({ waitUntil: "networkidle" }),
    rotateForm.getByRole("button", { name: "Rotate key" }).click(),
  ]);
  const issuedKeyCopy = page.locator(".copy-value").first();
  await issuedKeyCopy.click();
  await expect(issuedKeyCopy).toHaveText("Copy failed");
  await expect(page.locator("#clipboard-status")).toHaveAttribute("role", "alert");
  expect(pageErrors).toEqual([]);
  await seedWorker();
});

test("static demo mirrors verification, focused errors, and clipboard recovery", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async () => { throw new Error("demo clipboard denied by test"); },
      },
    });
  });
  await page.goto(`${demoBaseUrl}/demo/`, { waitUntil: "networkidle" });

  const check = page.locator("#turnstileCheck");
  const status = page.locator("#turnstileStatus");
  const submit = page.locator("#submitBtn");
  await check.check();
  await expect(status).toHaveText("Verification complete.");
  await expect(submit).toBeEnabled();
  await check.uncheck();
  await expect(status).toHaveAttribute("role", "alert");
  await expect(status).toContainText("Verification expired");
  await expect(submit).toBeDisabled();
  await page.locator("#turnstileRetry").click();
  await expect(check).toBeFocused();

  await check.check();
  await page.locator("#invite_key").fill("invalid-demo-key");
  await submit.click();
  await expect(page.locator("#allowFormStatus")).toBeVisible();
  await expect(page.locator("#allowFormStatus")).toBeFocused();
  await page.locator("#invite_key").fill("demo-key-001");
  await submit.click();
  await expect(page.getByRole("heading", { name: "Northwind Lab" })).toBeVisible();

  const copyButton = page.locator(".copy-value").first();
  await copyButton.click();
  await expect(copyButton).toHaveText("Copy failed");
  await expect(page.locator("#copyStatus")).toHaveAttribute("role", "alert");
  await expect(page.locator("#copyStatus")).toContainText("Select the value and copy it manually");
});

for (const viewport of VIEWPORTS) {
  for (const theme of THEMES) {
    test(`${viewport.name} ${theme} responsive matrix`, async ({ page, context }) => {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
      await page.addInitScript(installVitalsObserver);
      await page.route("https://challenges.cloudflare.com/**", turnstileRoute);
      await context.setExtraHTTPHeaders({ "CF-Connecting-IP": CLIENT_IP });
      await context.addCookies([{
        name: "sub2api_allow_admin",
        value: ADMIN_SESSION_TOKEN,
        domain: "api.example.test",
        path: "/allow-ip/admin",
        httpOnly: true,
        secure: false,
        sameSite: "Strict",
      }]);
      const decoderPage = await context.newPage();

      await captureScenario(page, decoderPage, viewport, theme, "public-form", `${workerBaseUrl}/allow-ip`);
      await context.addCookies([{
        name: "sub2api_allow_uuid",
        value: PUBLIC_SESSION_TOKEN,
        domain: "api.example.test",
        path: "/allow-ip",
        httpOnly: true,
        secure: false,
        sameSite: "Strict",
      }]);
      await captureScenario(page, decoderPage, viewport, theme, "public-dashboard", `${workerBaseUrl}/allow-ip`);
      await captureScenario(page, decoderPage, viewport, theme, "admin-list", `${workerBaseUrl}/allow-ip/admin`);
      await captureScenario(page, decoderPage, viewport, theme, "admin-create", `${workerBaseUrl}/allow-ip/admin?view=create`);
      await captureScenario(page, decoderPage, viewport, theme, "admin-maintenance", `${workerBaseUrl}/allow-ip/admin?view=maintenance`);
      await captureScenario(page, decoderPage, viewport, theme, "admin-detail", `${workerBaseUrl}/allow-ip/admin?detail=${PUBLIC_UUID}`);
      await captureScenario(page, decoderPage, viewport, theme, "usage-list", `${workerBaseUrl}/allow-ip/admin/requests`);
      await captureScenario(page, decoderPage, viewport, theme, "usage-detail", `${workerBaseUrl}/allow-ip/admin/requests/detail?id=9000`);
      await captureScenario(page, decoderPage, viewport, theme, "demo", `${demoBaseUrl}/demo/`);
      await decoderPage.close();
    });
  }
}

test("200 percent zoom equivalent reflows at 240 CSS px", async ({ page, context }) => {
  const viewport = { name: "zoom-200-equivalent-240x400", width: 240, height: 400 };
  await page.setViewportSize({ width: viewport.width, height: viewport.height });
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  await page.addInitScript(installVitalsObserver);
  await page.route("https://challenges.cloudflare.com/**", turnstileRoute);
  await context.setExtraHTTPHeaders({ "CF-Connecting-IP": CLIENT_IP });
  await context.addCookies([{
    name: "sub2api_allow_admin",
    value: ADMIN_SESSION_TOKEN,
    domain: "api.example.test",
    path: "/allow-ip/admin",
    httpOnly: true,
    secure: false,
    sameSite: "Strict",
  }]);
  const decoderPage = await context.newPage();
  await captureScenario(page, decoderPage, viewport, "light", "public-form", `${workerBaseUrl}/allow-ip`);
  await context.addCookies([{
    name: "sub2api_allow_uuid",
    value: PUBLIC_SESSION_TOKEN,
    domain: "api.example.test",
    path: "/allow-ip",
    httpOnly: true,
    secure: false,
    sameSite: "Strict",
  }]);
  await captureScenario(page, decoderPage, viewport, "light", "public-dashboard", `${workerBaseUrl}/allow-ip`);
  await captureScenario(page, decoderPage, viewport, "light", "admin-detail", `${workerBaseUrl}/allow-ip/admin?detail=${PUBLIC_UUID}`);
  await captureScenario(page, decoderPage, viewport, "light", "admin-create", `${workerBaseUrl}/allow-ip/admin?view=create`);
  await captureScenario(page, decoderPage, viewport, "light", "admin-maintenance", `${workerBaseUrl}/allow-ip/admin?view=maintenance`);
  await captureScenario(page, decoderPage, viewport, "light", "usage-list", `${workerBaseUrl}/allow-ip/admin/requests`);
  await captureScenario(page, decoderPage, viewport, "light", "demo", `${demoBaseUrl}/demo/`);
  await decoderPage.close();
});
