module.exports = {
    create: function () {
        return {
            outputCollector: {},

            startCompliance: function(plugin, pluginKey, compliance) {
            },

            endCompliance: function(plugin, pluginKey, compliance) {
            },

            writeResult: function (result, plugin, pluginKey) {
                if(!this.outputCollector[plugin.title]) {
                    this.outputCollector[plugin.title] = []
                }
                this.outputCollector[plugin.title].push(result)
            },

            close: function () {
            }
        }
    }
}