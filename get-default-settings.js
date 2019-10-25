#!/usr/bin/env node
const providers = require('./exports');

// Settings in plugins have this structure
// "settings": {
//   "service_limit_percentage_fail": {
//     "name": "Service Limit Percentage Fail",
//     "description": "Return a failing result when utilized services equals or exceeds this percentage",
//     "regex": "^(100|[1-9][0-9]?)$",
//     "default": 90
//   }
// }
// Then the plugins get the value from the settings object by referencing the same key
// e.g. settings['service_limit_percentage_fail']
//
// thus there are two keys in the output from this file for each settings. One is used by the plugin on execution, the
// second for infomational purposes only
//
// "service_limit_percentage_warn_description": { // this is for information only
//   "name": "Service Limit Percentage Warn",
//   "description": "Return a warning result when utilized services equals or exceeds this percentage",
//   "regex": "^(100|[1-9][0-9]?)$",
//   "default": 75
// },
// "service_limit_percentage_warn": 75 // plugin reads this value

const settings = {};

for (let providerName in providers) {
  for (let pluginName in providers[providerName]) {
    const plugin = providers[providerName][pluginName];
    for (let settingName in plugin.settings || {}) {
      settings[settingName + '_description'] = plugin.settings[settingName];
      settings[settingName] = plugin.settings[settingName].default;
    }
  }
}

console.log(JSON.stringify(settings, null, 2));