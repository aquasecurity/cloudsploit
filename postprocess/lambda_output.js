module.exports = {
  create: function () {
      //Could add other collectors here if memory becomes an issue.
      //Refer to output.js for what that would look like.
      return {
          collectionData: {},
          ResultsData: {},
          startCompliance: function(plugin, pluginKey, compliance) {
          },

          endCompliance: function(plugin, pluginKey, compliance) {
          },

          writeResult: function (result, plugin, pluginKey) {
              if(!this.ResultsData[plugin.title]) {
                  this.ResultsData[plugin.title] = []
              }
              this.ResultsData[plugin.title].push(result)
          },

          writeCollection(collection, serviceProviderName) {
            this.collectionData[serviceProviderName] = {collection}
          },

          close: function () {
          },

          getResuls: function() {
              return {
                collectionData: this.collectionData,
                ResultsData: this.ResultsData,
              }
          }
      }
  }
}
