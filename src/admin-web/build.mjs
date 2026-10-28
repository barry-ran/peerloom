import {copyFile,mkdir} from 'node:fs/promises';
await mkdir('dist/assets',{recursive:true});
await copyFile('index.html','dist/index.html');
await copyFile('src/style.css','dist/assets/style.css');
const embedded = '../device-server/internal/adminweb/assets';
await mkdir(embedded,{recursive:true});
await copyFile('dist/index.html',`${embedded}/index.html`);
await copyFile('dist/assets/app.js',`${embedded}/app.js`);
await copyFile('dist/assets/style.css',`${embedded}/style.css`);
