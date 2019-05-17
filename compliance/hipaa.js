// Defines a way of filtering plugins for those plugins that are related to
// HIPAA controls. The HIPAA information is defined inline, so this compliance
// checks for that information on the plugin.
module.exports = {
    describe: function (pluginId, plugin) {
        return plugin.compliance && plugin.compliance.hipaa;
    },

    includes: function (pluginId, plugin) {
        return plugin.compliance && plugin.compliance.hipaa;
    }
};
