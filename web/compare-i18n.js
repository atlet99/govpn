const fs = require('fs');

const enFile = JSON.parse(fs.readFileSync('./src/i18n/locales/en.json', 'utf8'));
const ruFile = JSON.parse(fs.readFileSync('./src/i18n/locales/ru.json', 'utf8'));

function getKeys(obj, prefix = '') {
  let keys = [];
  for (const key in obj) {
    if (typeof obj[key] === 'object' && obj[key] !== null) {
      keys = keys.concat(getKeys(obj[key], prefix + key + '.'));
    } else {
      keys.push(prefix + key);
    }
  }
  return keys;
}

const enKeys = getKeys(enFile).sort();
const ruKeys = getKeys(ruFile).sort();

console.log('EN file contains', enKeys.length, 'keys');
console.log('RU file contains', ruKeys.length, 'keys');

const missingInRu = enKeys.filter(key => !ruKeys.includes(key));
const missingInEn = ruKeys.filter(key => !enKeys.includes(key));

if (missingInRu.length > 0) {
  console.log('\nKeys missing in RU file:');
  missingInRu.forEach(key => console.log('  -', key));
}

if (missingInEn.length > 0) {
  console.log('\nKeys missing in EN file:');
  missingInEn.forEach(key => console.log('  -', key));
}

if (missingInRu.length === 0 && missingInEn.length === 0) {
  console.log('\n✅ Files contain the same keys!');
} else {
  console.log('\n❌ Found differences in keys.');
}

// Additional check for duplicate keys in the RU file
const ruDuplicates = ruKeys.filter((item, index) => ruKeys.indexOf(item) !== index);
if (ruDuplicates.length > 0) {
  console.log('\nDuplicate keys in RU file:');
  ruDuplicates.forEach(key => console.log('  -', key));
} 