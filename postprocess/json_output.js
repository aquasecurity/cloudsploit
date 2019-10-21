module.exports = {
    create: function () {
        //Could possible add other collectors here if memory does in fact become an issue.
        //Refer to output.js for what that would look like.
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
            },

            getOutput: function() {
                return this.outputCollector
            }
        }
    }
}