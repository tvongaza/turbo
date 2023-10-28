import { test } from "@playwright/test"
import { assert } from "chai"
import {
  readCspViolations
} from "../helpers/page"

test.describe('ReportingObserver supported', () => {
  test.skip(async ({ page }) => { return page.evaluate(() => typeof window.ReportingObserver !== 'function') }, "ReportingObserver is not supported in this environment")

  test("Content Security Policy - reject all", async ({ page }) => {
    await page.goto("/__turbo/csp?default-src='none'&script-src='nonce-testHelpers'&file=../../src/tests/fixtures/content_security_policy_without_nonce.html")

    const cspReports = await readCspViolations(page, 10)
    assert.equal(cspReports.length, 1, "reports CSP violations")
    assert.equal(cspReports[0].body.blockedURL, "http://localhost:9000/dist/turbo.es2017-umd.js", "CSP violation blockedURL")
  })

  test("Content Security Policy - script-src-elem=self", async ({ page }) => {
    await page.goto("/__turbo/csp?default-src='self'&script-src-elem='self' 'nonce-testHelpers'&file=../../src/tests/fixtures/content_security_policy_without_nonce.html")

    const cspReports = await readCspViolations(page, 10)
    assert.equal(cspReports.length, 1, "reports CSP violations")
    assert.equal(cspReports[0].body.effectiveDirective, "style-src-elem", "CSP violation directive (style-src-elem)")
    assert.equal(cspReports[0].body.blockedURL, "inline", "CSP violation blockedURL (inline)")
  })

  test("Content Security Policy - script-src-elem=self&style-src-elem=unsafe-inline", async ({ page }) => {
    await page.goto("/__turbo/csp?default-src='self'&script-src-elem='self' 'nonce-testHelpers'&style-src-elem='unsafe-inline'&file=../../src/tests/fixtures/content_security_policy_without_nonce.html")

    assert.equal(
      await page.locator("style").evaluate((style) => style.nonce),
      "",
      "renders progress bar stylesheet inline without nonce"
    )
    assert.equal((await readCspViolations(page, 10)).length, 0, "reports no CSP violations")
  })

  test("Content Security Policy - script-src-elem=self&style-src-elem=nonce=123", async ({ page, browserName }) => {
    await page.goto("/__turbo/csp?default-src='self'&script-src-elem='self' 'nonce-testHelpers'&style-src-elem='nonce-123'&file=../../src/tests/fixtures/content_security_policy_with_nonce.html")

    assert.equal(
      await page.locator("style").evaluate((style) => style.nonce),
      "123",
      "renders progress bar stylesheet inline with nonce"
    )
    assert.equal((await readCspViolations(page, 10)).length, 0, "reports no CSP violations")
  })

  test("Content Security Policy - script-src-elem=self&style-src-elem='self' 'sha256-WAyOw4V+FqDc35lQPyRADLBWbuNK8ahvYEaQIYF1+Ps='", async ({ page }) => {
    const progressBarStyleHash = encodeURIComponent("sha256-WAyOw4V+FqDc35lQPyRADLBWbuNK8ahvYEaQIYF1+Ps=");
    await page.goto(`/__turbo/csp?default-src='self'&script-src-elem='self' 'nonce-testHelpers'&style-src-elem='self' '${progressBarStyleHash}'&file=../../src/tests/fixtures/content_security_policy_without_nonce.html`)

    assert.equal(
      await page.locator("style").evaluate((style) => style.nonce),
      "",
      "renders progress bar stylesheet inline without nonce"
    )
    assert.equal((await readCspViolations(page, 10)).length, 0, "reports no CSP violations")
  })
})
