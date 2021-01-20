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
            var handler = output.createJunit(buffer, {mocha: true, junit: 'test.junit'});
            handler.close();
            expect(buffer.cache).to.equal(
                '<?xml version="1.0" encoding="UTF-8" ?>\n' + 
                '<testsuites>\n</testsuites>\n');
        })

        it('should indicate one pass there is one passing result', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJunit(buffer, { mocha: true, junit: 'test.junit' });
            handler.writeResult({status: 0}, {title:'myTitle'}, 'key');
            handler.close();

            expect(buffer.cache).to.include(' tests="1" ');
            expect(buffer.cache).to.include(' failures="0" ');
            expect(buffer.cache).to.include(' errors="0" ');
        })

        it('should indicate one failure there is one failing result', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJunit(buffer, { mocha: true, junit: 'test.junit' });
            handler.writeResult({status: 2, message: 'fail message'}, {title:'myTitle'}, 'key');
            handler.close();

            expect(buffer.cache).to.include(' tests="1" ');
            expect(buffer.cache).to.include(' failures="1" ');
            expect(buffer.cache).to.include(' errors="0" ');
            expect(buffer.cache).to.include('fail message');
        })

        it('should indicate one error there is one failing error', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJunit(buffer, { mocha: true, junit: 'test.junit' });
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
            var handler = output.createCsv(buffer, { mocha: true, junit: 'test.csv' });
            handler.close();
            expect(buffer.cache).to.equal('');
        })

        it('should indicate one pass there is one passing result', function () {
            var buffer = createOutputBuffer();
            var handler = output.createCsv(buffer, { mocha: true, junit: 'test.csv' });
            handler.writeResult({status: 0}, {title:'myTitle', description: 'myDescription'}, 'key');
            handler.close();
            expect(buffer.cache).to.equal('category,title,description,resource,region,statusWord,message\n,myTitle,myDescription,N/A,Global,OK,\n');
        })
    })

    describe('json', function () {
        it('should generate empty array if no results', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJson(buffer, { mocha: true, junit: 'test.json' });
            handler.close();
            expect(buffer.cache).to.equal('[]');
        })

        it('should indicate one pass there is one passing result', function () {
            var buffer = createOutputBuffer();
            var handler = output.createJson(buffer, { mocha: true, junit: 'test.json' });
            handler.writeResult({ status: 0 }, { title: 'myTitle', description: 'myDescription' }, 'key');
            handler.close();
            expect(JSON.stringify(JSON.parse(buffer.cache))).to.equal('[{"plugin":"key","title":"myTitle","description":"myDescription","resource":"N/A","region":"Global","status":"OK"}]');
        })
    })

    describe('create', function() {
        it('should write to console without errors', function () {
            // Create with no arguments is valid and just says create the
            // default, which is console output.
            var handler = output.create([])

            handler.writeResult({status: 0, message: 'Certificate has validation enabled'}, {
                category: 'ACM',
                title:'ACM Certificate Validation',
                description: 'Testing the ACM certificate which must have DNS validation enabled'
            }, 'key');
            handler.close();
            // No expect here because in the current structure, we cannot
            // capture the standard output
        })

        it('should handle compliance sections without errors', function () {
            // Create with no arguments is valid and just says create the
            // default, which is console output.
            var handler = output.create([]);

            handler.writeResult({ status: 0, message: 'Certificate has validation enabled'}, {
                category: 'ACM',
                title: 'ACM Certificate Validation',
                description: 'Testing the ACM certificate which must have DNS validation enabled'
            }, 'key2', 'Compliance message');
            handler.close();
            // No expect here because in the current structure, we cannot
            // capture the standard output
        })
    })
})