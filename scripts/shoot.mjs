import { chromium } from "playwright";

const BASE = "http://localhost:8899";
const DOCS = new URL("../docs/", import.meta.url).pathname;

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1340, height: 920 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();
const shot = async (name) => {
  await page.screenshot({ path: `${DOCS}${name}.png` });
  console.log("shot", name);
};

await page.goto(BASE, { waitUntil: "networkidle" });
await page.waitForTimeout(400);
await shot("signin");

// sign in as the admin persona (sandbox code auto-fills)
await page.getByText("Nishant Singh").first().click();
await page.getByRole("button", { name: /Verify & enter/ }).waitFor();
await page.waitForTimeout(300);
await shot("2fa");
await page.getByRole("button", { name: /Verify & enter/ }).click();

await page.getByRole("heading", { name: /Welcome/ }).waitFor();
await page.waitForTimeout(400);
await shot("overview");

// workspace + a decision
await page.getByRole("button", { name: /Workspace/ }).click();
await page.getByText("Payroll register").first().waitFor();
await page.waitForTimeout(300);
await shot("workspace");

await page.getByText("Payroll register").first().click();
await page.waitForTimeout(900); // let the trace animate in
await shot("decision-allow");
// close drawer
await page.keyboard.press("Escape");
await page.mouse.click(300, 300);

// segmentation
await page.getByRole("button", { name: /Segmentation/ }).click();
await page.waitForTimeout(400);
await shot("segmentation");

// admin → audit
await page.getByRole("button", { name: /Admin console/ }).click();
await page.getByRole("button", { name: /Audit trail/ }).click();
await page.getByRole("button", { name: /Verify integrity/ }).click();
await page.waitForTimeout(500);
await shot("audit");

// learn
await page.getByRole("button", { name: /How it works/ }).click();
await page.waitForTimeout(400);
await shot("learn");

// mobile sign-in
const m = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
const mp = await m.newPage();
await mp.goto(BASE, { waitUntil: "networkidle" });
await mp.waitForTimeout(400);
await mp.screenshot({ path: `${DOCS}mobile-signin.png` });
console.log("shot mobile-signin");

await browser.close();
console.log("done");
