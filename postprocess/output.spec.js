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

        it('should indicate one failure when there is one failing result', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJunit(buffer);
            handler.writeResult({status: 2, message: 'fail message'}, {title:'myTitle'}, 'key');
            handler.close();

            expect(buffer.cache).to.include(' tests="1" ');
            expect(buffer.cache).to.include(' failures="1" ');
            expect(buffer.cache).to.include(' errors="0" ');
            expect(buffer.cache).to.include('fail message');
        })

        it('should indicate one error when there is one failing error', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJunit(buffer);
            handler.writeResult({status: 3, message: 'error message'}, {title:'myTitle'}, 'key');
            handler.close();

            expect(buffer.cache).to.include(' tests="1" ');
            expect(buffer.cache).to.include(' failures="0" ');
            expect(buffer.cache).to.include(' errors="1" ');
            expect(buffer.cache).to.include('error message');
        })

        it('should escape XML output if it contains special characters', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJunit(buffer, new Date(Date.UTC(2019, 04, 08, 16, 21, 46)));
            handler.writeResult({status: 3, message: 'resource <> has characters'}, {title:'"special" char'}, '&key');
            handler.close();

            var expected = ('<?xml version="1.0" encoding="UTF-8" ?>\n' +
                            '<testsuites>\n' +
                            '\t<testsuite name="&quot;special&quot; char: " hostname="localhost" tests="1" errors="1" failures="0" timestamp="2019-05-08T16:21:46" time="0" package="&amp;key" id="0">\n' +
                            '\t\t<properties></properties>\n' +
                            '\t\t<testcase classname="&amp;key" name="undefined; N/A; resource &lt;&gt; has characters" time="0">\n' +
                            '\t\t\t<failure message="resource &lt;&gt; has characters" type="none"/>\n' +
                            '\t\t</testcase>\n' +
                            '\t\t<system-out></system-out>\n' +
                            '\t\t<system-err></system-err>\n' +
                            '\t</testsuite>\n' +
                            '</testsuites>\n')

            expect(buffer.cache).to.equal(expected)
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