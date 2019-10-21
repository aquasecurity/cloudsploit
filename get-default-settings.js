const providers = require('./exports');

const settings = {
  defaults: {},
  meta: {},
};

for (let providerName in providers) {
  for (let pluginName in providers[providerName]) {
    const plugin = providers[providerName][pluginName];
    for (let settingName in plugin.settings || {}) {
      settings.defaults[settingName] = plugin.settings[settingName].default;
      settings.meta[settingName] = plugin.settings[settingName];
    }
  }
}

console.log(JSON.stringify(settings));
