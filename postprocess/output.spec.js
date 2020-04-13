var assert = require('assert');
var expect = require('chai').expect;
var output = require('./output')

/**
 * Creates an object that looks like an output stream that we can write
 * to (but is actually just a buffer caching the data)
 */
var createOutputBuffer = function () {
    return {
        cache: '',

        write: function (data) {
            this.cache += data;
        },

        end: function () {},
        on: function (event, fn) {},
        once: function(event, fn) {},
        emit: function(even, fn) {}
    }
}

describe('output', function () {
    describe('junit', function () {
        it('should generate empty junit when no results', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJunit(buffer);
            handler.close();
            expect(buffer.cache).to.equal(
                '<?xml version="1.0" encoding="UTF-8" ?>\n' +
                '<testsuites>\n</testsuites>\n');
        })

        it('should indicate one pass there is one passing result', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJunit(buffer);
            handler.writeResult({status: 0}, {title:'myTitle'}, 'key');
            handler.close();

            expect(buffer.cache).to.include(' tests="1" ');
            expect(buffer.cache).to.include(' failures="0" ');
            expect(buffer.cache).to.include(' errors="0" ');
        })

        it('should indicate one failure there is one failing result', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJunit(buffer);
            handler.writeResult({status: 2, message: 'fail message'}, {title:'myTitle'}, 'key');
            handler.close();

            expect(buffer.cache).to.include(' tests="1" ');
            expect(buffer.cache).to.include(' failures="1" ');
            expect(buffer.cache).to.include(' errors="0" ');
            expect(buffer.cache).to.include('fail message');
        })

        it('should indicate one error there is one failing error', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJunit(buffer);
            handler.writeResult({status: 3, message: 'error message'}, {title:'myTitle'}, 'key');
            handler.close();

            expect(buffer.cache).to.include(' tests="1" ');
            expect(buffer.cache).to.include(' failures="0" ');
            expect(buffer.cache).to.include(' errors="1" ');
            expect(buffer.cache).to.include('error message');
        })
    })

    describe('csv', function () {
        it('should generate only header if no results', function () {
            var buffer = createOutputBuffer();
            var handler = output.createCsv(buffer);
            handler.close();
            expect(buffer.cache).to.equal('');
        })

        it('should indicate one pass there is one passing result', function () {
            var buffer = createOutputBuffer();
            var handler = output.createCsv(buffer);
            handler.writeResult({status: 0}, {title:'myTitle'}, 'key');
            handler.close();
            expect(buffer.cache).to.equal('category,title,resource,region,statusWord,message\n,myTitle,N/A,Global,OK,\n');
        })
    })

    describe('json', function () {
        it('should generate empty array if no results', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJson(buffer);
            handler.close();
            expect(buffer.cache).to.equal('[]');
        })

        it('should indicate one pass there is one passing result', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJson(buffer);
            handler.writeResult({status: 0}, {title:'myTitle'}, 'key');
            handler.close();
            expect(buffer.cache).to.equal('[{"plugin":"key","title":"myTitle","resource":"N/A","region":"Global","status":"OK","statusNumber":0}]');
        })
    })

    describe('multiplexer', function () {
        it('should write to all outputs', function () {
            var buffer1 = createOutputBuffer();
            var buffer2 = createOutputBuffer();
            var jsonOutput1 = output.createJson(buffer1);
            var jsonOutput2 = output.createJson(buffer2);
            var multiplexer = output.multiplexer([jsonOutput1, jsonOutput2], [], false);
            multiplexer.writeResult({status: 0}, {title:'myTitle'}, 'key');
            multiplexer.close();
            expect(buffer1.cache).to.equal(buffer2.cache);
            expect(buffer1.cache).to.equal('[{"plugin":"key","title":"myTitle","resource":"N/A","region":"Global","status":"OK","statusNumber":0}]');
        })
        it('should write to all collectionOutputs', function () {
            var buffer1 = createOutputBuffer();
            var buffer2 = createOutputBuffer();
            var collectionOutput1 = output.createCollection(buffer1);
            var collectionOutput2 = output.createCollection(buffer2);
            var multiplexer = output.multiplexer([], [collectionOutput1, collectionOutput2], false);
            multiplexer.writeCollection({some: 'data'}, 'AWS');
            multiplexer.close();
            expect(buffer1.cache).to.equal(buffer2.cache);
            expect(buffer1.cache).to.equal('{"AWS":{"some":"data"}}');
        })
    })

    describe('create', function() {
        it('should write to console without errors', function () {
            // Create with no arguments is valid and just says create the
            // default, which is console output.
            var handler = output.create([])

            handler.writeResult({status: 0}, {title:'myTitle'}, 'key');
            handler.close();
            // No expect here because in the current structure, we cannot
            // capture the standard output
        })

        it('should handle compliance sections without errors', function () {
            // Create with no arguments is valid and just says create the
            // default, which is console output.
            var handler = output.create([]);

            // Create the information about the compliance rule - for this
            // test, it doesn't have to be anything fancy
            var complianceRule = {
                describe: function (pluginKey, plugin) {
                    return 'desc';
                }
            };
            var plugin = {
                title: 'title'
            };
            var pluginKey = 'someIdentifier';

            handler.startCompliance(plugin, pluginKey, complianceRule);
            handler.writeResult({status: 0}, {title:'myTitle'}, 'key');
            handler.endCompliance(plugin, pluginKey, complianceRule);
            handler.close();
            // No expect here because in the current structure, we cannot
            // capture the standard output
        })
    })
})