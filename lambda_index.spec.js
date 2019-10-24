var indexHandler = require('./lambda_index.js').handler
var chai = require('chai');
var chaiAsPromised = require("chai-as-promised")
var expect = require('chai').expect;
chai.use(chaiAsPromised)

var cloudwatchEventAccountId = {
    "id": "cdc73f9d-aea9-11e3-9d5a-835b769c0d9c",
    "detail-type": "Scheduled Event",
    "source": "aws.events",
    "account": "{{{account-id}}}",
    "time": "1970-01-01T00:00:00Z",
    "region": "us-east-1",
    "resources": [
        "arn:aws:events:us-east-1:123456789012:rule/ExampleRule"
    ],
    "detail": {
        "aws": {
            "account_id": "454679818906"
        }
    }
}

var lambdaContext = {
    'aws_request_id': 'a3de505e-f16b-42f4-b3e6-bcd2e4a73903',
    'log_stream_name': '2015/10/26/[$LATEST]c71058d852474b9895a0f221f73402ad',
    'invokedFunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:function-name',
    'client_context': '',
    'log_group_name': '/aws/lambda/ExampleCloudFormationStackName-ExampleLambdaFunctionResourceName-AULC3LB8Q02F',
    'function_name': 'ExampleCloudFormationStackName-ExampleLambdaFunctionResourceName-AULC3LB8Q02F',
    'function_version': '$LATEST',
    'memory_limit_in_mb': '128'
}

describe('handler', function() {
    it('should return ok', async function() {
        this.timeout(60000)
        var out = await indexHandler(cloudwatchEventAccountId, lambdaContext)
        expect(out).to.equal('Ok')
    })
})
