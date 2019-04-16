// Defines a way of filters that includes all rules. This is the default
// compliance filter if there is no other defined filter.
module.exports = {
    describe: function(pluginId, plugin) {
        return ''
    },

    includes: function (pluginId, plugin) {
        // We include all plugins, so just return true
        return true
    }
}