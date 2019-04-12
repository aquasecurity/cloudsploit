var csvWriter = require('csv-write-stream');
var fs = require('fs');

// For the console output, we don't need any state since we can write
// directly to the console.
var consoleOutputHandler = {
    startCompliance: function(plugin, pluginKey, compliance) {
        var complianceDesc = compliance.describe(pluginKey, plugin)
        if (complianceDesc) {
            console.log('');
            console.log('-----------------------');
            console.log(plugin.title);
            console.log('-----------------------');
            console.log(complianceDesc);
            console.log('');
        }
    },

    endCompliance: function(plugin, pluginKey, compliance) {
        // For console output, we don't do anything
    },

    writeResult: function (result, plugin, pluginKey) {
        var statusWord;
        if (result.status === 0) {
            statusWord = 'OK';
        } else if (result.status === 1) {
            statusWord = 'WARN';
        } else if (result.status === 2) {
            statusWord = 'FAIL';
        } else {
            statusWord = 'UNKNOWN';
        }

        console.log(plugin.category + '\t' + plugin.title + '\t' +
						(result.resource || 'N/A') + '\t' +
						(result.region || 'Global') + '\t\t' +
						statusWord + '\t' + result.message);
    }
}

// Defines a way to write to CSV output. To use this, set the writer
// property and then you can write results to CSV.
var csvOutputHandler = {
    writer: undefined,

    startCompliance: function(plugin, pluginKey, compliance) {
    },

    endCompliance: function(plugin, pluginKey, compliance) {
    },

    writeResult: function (result, plugin, pluginKey) {
        var statusWord;
        if (result.status === 0) {
            statusWord = 'OK';
        } else if (result.status === 1) {
            statusWord = 'WARN';
        } else if (result.status === 2) {
            statusWord = 'FAIL';
        } else {
            statusWord = 'UNKNOWN';
        }

        this.writer.write([plugin.category, plugin.title, (result.resource || 'N/A'), (result.region || 'Global'), statusWord, result.message])
    },

    close: function () {
        this.writer.end()
    }
}

module.exports = {
    create: function (argv) {
        var outputs = [];

        // Creates the handlers for writing output.
        var addCsvOutput = argv.find(function (arg) {
            return arg.startsWith('--csv=')
        })
        if (addCsvOutput) {
            var writer = csvWriter({headers: ['category', 'title', 'resource', 'region', 'statusWord', 'message']});
            writer.pipe(fs.createWriteStream(addCsvOutput.substr(6)));
            csvOutputHandler.writer = writer
            outputs.push(csvOutputHandler);
        }

        var addConsoleOutput = argv.find(function (arg) {
            return arg.startsWith('--console');
        })
        // Write to console if specified or by default if there is not
        // other output handler specified.
        if (addConsoleOutput || outputs.length == 0) {
            outputs.push(consoleOutputHandler);
        }

        // This creates a multiplexer-like object that forwards the
        // call onto any output handler that has been defined. This
        // allows us to simply send the output to multiple handlers
        // and the caller doesn't need to worry about that part.
        return {
            startCompliance: function(plugin, pluginKey, compliance) {
                for (var output of outputs) {
                    output.startCompliance(plugin, pluginKey, compliance);
                }
            },

            endCompliance: function(plugin, pluginKey, compliance) {
                for (var output of outputs) {
                    output.endCompliance(plugin, pluginKey, compliance);
                }
            },

            writeResult: function (result, plugin, pluginKey) {
                for (var output of outputs) {
                    output.writeResult(result, plugin, pluginKey);
                }
            },

            close: function () {
                for (var output of outputs) {
                    output.close();
                }
            }
        }
    }
}