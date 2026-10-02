import fs from 'node:fs';

const html = fs.readFileSync('src/dashboard.html', 'utf-8');
fs.writeFileSync('src/dashboard.ts', `const dashboardHtml: string = ${JSON.stringify(html)};\nexport default dashboardHtml;\n`);
console.log('Synced dashboard.html to dashboard.ts');
