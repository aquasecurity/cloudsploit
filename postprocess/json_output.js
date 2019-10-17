module.exports = {
    create: function () {
        //because of the callback on engine, this isn't entirely needed since both callbacks would be called at the same time (and do the same thing).
        return {
            outputCollector: {},

            startCompliance: function(plugin, pluginKey, compliance) {
            },

            endCompliance: function(plugin, pluginKey, compliance) {
            },

            writeResult: function (result, plugin, pluginKey) {
                if(!plugin.title in outputCollector) {
                    outputCollector[plugin.title] = []
                }
                outputCollector[plugin.title].push(result)
            },

            close: function () {
            }
        }
    }
}