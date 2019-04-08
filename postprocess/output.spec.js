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

    describe('create', function () {
        it('should create a console output if no arguments specified', function () {
            // We don't have any asserts for this test - but it would be nice
            // sometime to redirect the console output.
            var handler = output.create([])

            var plugin = {}

            var complianceItem = {
                describe: (pluginKey, plugin) => { return 'Description'}
            }

            handler.startCompliance(plugin, 'pluginKey', complianceItem)
            handler.writeResult({status: 0}, {title:'myTitle'}, 'key');
            handler.endCompliance(plugin, 'pluginKey', complianceItem)
            handler.close()
        })
    })
})