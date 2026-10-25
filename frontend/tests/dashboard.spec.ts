import { test, expect } from '@playwright/test';

test('real API: baseline, path highlights, protected asset, original graph retained', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText('Engine analysis ready')).toBeVisible();
  await expect(page.locator('.asset-row')).toContainText('Customer database');
  await expect(page.locator('.path-inspector')).toContainText('login → ssh → db-read');
  await expect(page.locator('.react-flow__edge.animated')).toHaveCount(3);
  await page.getByLabel('Permission to remove').selectOption('db-read');
  const response = page.waitForResponse(r => r.url().endsWith('/api/analyze') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Simulate removal' }).click();
  const analysis = await response;
  expect(analysis.status()).toBe(200);
  expect(analysis.request().postDataJSON().simulations).toEqual([{ id: 'revoke-selected', remove_edges: ['db-read'] }]);
  await expect(page.getByTestId('simulation-result')).toContainText('1 asset protected: Customer database');
  await expect(page.getByText('No sensitive assets reachable.')).toBeVisible();
  await expect(page.locator('.react-flow__edge')).toHaveCount(4);
  await page.getByRole('button', { name: 'Baseline', exact: true }).click();
  await expect(page.locator('.asset-row')).toContainText('Customer database');
  await page.getByRole('button', { name: 'Clear simulation' }).click();
  await expect(page.getByTestId('simulation-result')).toHaveCount(0);
});

test('real API: alternate route remains exposed and source changes reset results', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('SYNTHETIC ENVIRONMENT').selectOption('redundant');
  await expect(page.getByText('Engine analysis ready')).toBeVisible();
  await page.locator('.asset-row').filter({ hasText: 'Data vault' }).click();
  await expect(page.locator('.path-inspector')).toContainText('a → c');
  await page.getByLabel('Permission to remove').selectOption('c');
  await page.getByRole('button', { name: 'Simulate removal' }).click();
  await expect(page.getByTestId('simulation-result')).toContainText('An attack path still exists');
  await page.locator('.asset-row').filter({ hasText: 'Data vault' }).click();
  await expect(page.locator('.path-inspector')).toContainText('b → d');
  await expect(page.locator('.asset-row').filter({ hasText: 'Data vault' })).toContainText('Remains exposed');
  await page.getByLabel('Compromised source', { exact: true }).selectOption('vault');
  await expect(page.getByText('Engine analysis ready')).toBeVisible();
  await expect(page.getByTestId('simulation-result')).toHaveCount(0);
  await expect(page.locator('.path-inspector')).toContainText('0 hops');
});

test('connection errors are actionable and retry works', async ({ page }) => {
  await page.route('**/api/analyze', route => route.abort());
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('Start FastAPI');
  await page.unroute('**/api/analyze');
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByText('Engine analysis ready')).toBeVisible();
});

test('mobile layout fits the viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await expect(page.locator('.asset-row')).toContainText('Customer database');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expect(page.getByLabel('Compromised source', { exact: true })).toBeVisible();
});
