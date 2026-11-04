// Optional maintenance tool; Node is not needed to build or run the native app.
import fs from 'node:fs/promises';
const result = {};
for (const locale of ['en', 'fr', 'de', 'es', 'pt-BR', 'ru', 'ja', 'zh-CN']) {
  const source = await fs.readFile(new URL(`../ui/src/locales/${locale}.js`, import.meta.url), 'utf8');
  const dictionary = (await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)).default;
  result[locale] = Object.fromEntries(Object.entries(dictionary).filter(([, value]) => typeof value === 'string'));
}
await fs.writeFile(new URL('../desktop/assets/locales/upstream.json', import.meta.url), JSON.stringify(result, null, 2) + '\n');
