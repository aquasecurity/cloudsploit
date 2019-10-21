module.exports = {
    create: function () {
        //Could possible add other collectors here if memory does in fact become an issue.
        //Refer to output.js for what that would look like.
        return {
            outputCollector: {},

            startCompliance: (plugin, pluginKey, compliance) => {
            },

            endCompliance: (plugin, pluginKey, compliance) => {
            },

            writeResult: (result, plugin, pluginKey) => {
                if(!this.outputCollector[plugin.title]) {
                    this.outputCollector[plugin.title] = []
                }
                this.outputCollector[plugin.title].push(result)
            },

            close: () => {
            },

            getOutput: () => {
                return this.outputCollector
            }
        }
    }
}