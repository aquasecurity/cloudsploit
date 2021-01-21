var expect = require('chai').expect;
var regRegions = require(__dirname + '/helpers/aws/regions.js');
var govRegions = require(__dirname + '/helpers/aws/regions_gov.js');
var chinaRegions = require(__dirname + '/helpers/aws/regions_china.js');

describe('AWS Regions', function() {
    it('should have same regions for AWS, China, and GovCloud', function() {
        Object.keys(regRegions).forEach(function(regRegion){
            expect(govRegions[regRegion], `AWS Region: ${regRegion} is not present in GovCloud region list`).to.be.an('array');
            expect(chinaRegions[regRegion], `AWS Region: ${regRegion} is not present in China region list`).to.be.an('array');
        });
    });
});
