/**
 * @fileoverview gRPC-Web generated client stub for cosmos.bank.v1beta1
 * @enhanceable
 * @public
 */

// GENERATED CODE -- DO NOT EDIT!


/* eslint-disable */
// @ts-nocheck



const grpc = {};
grpc.web = require('grpc-web');


var cosmos_base_query_v1beta1_pagination_pb = require('../../../cosmos/base/query/v1beta1/pagination_pb.js')

var gogoproto_gogo_pb = require('../../../gogoproto/gogo_pb.js')

var google_api_annotations_pb = require('../../../google/api/annotations_pb.js')

var cosmos_base_v1beta1_coin_pb = require('../../../cosmos/base/v1beta1/coin_pb.js')

var cosmos_bank_v1beta1_bank_pb = require('../../../cosmos/bank/v1beta1/bank_pb.js')
const proto = {};
proto.cosmos = {};
proto.cosmos.bank = {};
proto.cosmos.bank.v1beta1 = require('./query_pb.js');

/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.cosmos.bank.v1beta1.QueryClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @param {string} hostname
 * @param {?Object} credentials
 * @param {?grpc.web.ClientOptions} options
 * @constructor
 * @struct
 * @final
 */
proto.cosmos.bank.v1beta1.QueryPromiseClient =
    function(hostname, credentials, options) {
  if (!options) options = {};
  options.format = 'text';

  /**
   * @private @const {!grpc.web.GrpcWebClientBase} The client
   */
  this.client_ = new grpc.web.GrpcWebClientBase(options);

  /**
   * @private @const {string} The hostname
   */
  this.hostname_ = hostname;

};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.cosmos.bank.v1beta1.QueryBalanceRequest,
 *   !proto.cosmos.bank.v1beta1.QueryBalanceResponse>}
 */
const methodDescriptor_Query_Balance = new grpc.web.MethodDescriptor(
  '/cosmos.bank.v1beta1.Query/Balance',
  grpc.web.MethodType.UNARY,
  proto.cosmos.bank.v1beta1.QueryBalanceRequest,
  proto.cosmos.bank.v1beta1.QueryBalanceResponse,
  /**
   * @param {!proto.cosmos.bank.v1beta1.QueryBalanceRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.cosmos.bank.v1beta1.QueryBalanceResponse.deserializeBinary
);


/**
 * @param {!proto.cosmos.bank.v1beta1.QueryBalanceRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.cosmos.bank.v1beta1.QueryBalanceResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.cosmos.bank.v1beta1.QueryBalanceResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.cosmos.bank.v1beta1.QueryClient.prototype.balance =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/cosmos.bank.v1beta1.Query/Balance',
      request,
      metadata || {},
      methodDescriptor_Query_Balance,
      callback);
};


/**
 * @param {!proto.cosmos.bank.v1beta1.QueryBalanceRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.cosmos.bank.v1beta1.QueryBalanceResponse>}
 *     Promise that resolves to the response
 */
proto.cosmos.bank.v1beta1.QueryPromiseClient.prototype.balance =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/cosmos.bank.v1beta1.Query/Balance',
      request,
      metadata || {},
      methodDescriptor_Query_Balance);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.cosmos.bank.v1beta1.QueryAllBalancesRequest,
 *   !proto.cosmos.bank.v1beta1.QueryAllBalancesResponse>}
 */
const methodDescriptor_Query_AllBalances = new grpc.web.MethodDescriptor(
  '/cosmos.bank.v1beta1.Query/AllBalances',
  grpc.web.MethodType.UNARY,
  proto.cosmos.bank.v1beta1.QueryAllBalancesRequest,
  proto.cosmos.bank.v1beta1.QueryAllBalancesResponse,
  /**
   * @param {!proto.cosmos.bank.v1beta1.QueryAllBalancesRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.cosmos.bank.v1beta1.QueryAllBalancesResponse.deserializeBinary
);


/**
 * @param {!proto.cosmos.bank.v1beta1.QueryAllBalancesRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.cosmos.bank.v1beta1.QueryAllBalancesResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.cosmos.bank.v1beta1.QueryAllBalancesResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.cosmos.bank.v1beta1.QueryClient.prototype.allBalances =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/cosmos.bank.v1beta1.Query/AllBalances',
      request,
      metadata || {},
      methodDescriptor_Query_AllBalances,
      callback);
};


/**
 * @param {!proto.cosmos.bank.v1beta1.QueryAllBalancesRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.cosmos.bank.v1beta1.QueryAllBalancesResponse>}
 *     Promise that resolves to the response
 */
proto.cosmos.bank.v1beta1.QueryPromiseClient.prototype.allBalances =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/cosmos.bank.v1beta1.Query/AllBalances',
      request,
      metadata || {},
      methodDescriptor_Query_AllBalances);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.cosmos.bank.v1beta1.QueryTotalSupplyRequest,
 *   !proto.cosmos.bank.v1beta1.QueryTotalSupplyResponse>}
 */
const methodDescriptor_Query_TotalSupply = new grpc.web.MethodDescriptor(
  '/cosmos.bank.v1beta1.Query/TotalSupply',
  grpc.web.MethodType.UNARY,
  proto.cosmos.bank.v1beta1.QueryTotalSupplyRequest,
  proto.cosmos.bank.v1beta1.QueryTotalSupplyResponse,
  /**
   * @param {!proto.cosmos.bank.v1beta1.QueryTotalSupplyRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.cosmos.bank.v1beta1.QueryTotalSupplyResponse.deserializeBinary
);


/**
 * @param {!proto.cosmos.bank.v1beta1.QueryTotalSupplyRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.cosmos.bank.v1beta1.QueryTotalSupplyResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.cosmos.bank.v1beta1.QueryTotalSupplyResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.cosmos.bank.v1beta1.QueryClient.prototype.totalSupply =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/cosmos.bank.v1beta1.Query/TotalSupply',
      request,
      metadata || {},
      methodDescriptor_Query_TotalSupply,
      callback);
};


/**
 * @param {!proto.cosmos.bank.v1beta1.QueryTotalSupplyRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.cosmos.bank.v1beta1.QueryTotalSupplyResponse>}
 *     Promise that resolves to the response
 */
proto.cosmos.bank.v1beta1.QueryPromiseClient.prototype.totalSupply =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/cosmos.bank.v1beta1.Query/TotalSupply',
      request,
      metadata || {},
      methodDescriptor_Query_TotalSupply);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.cosmos.bank.v1beta1.QuerySupplyOfRequest,
 *   !proto.cosmos.bank.v1beta1.QuerySupplyOfResponse>}
 */
const methodDescriptor_Query_SupplyOf = new grpc.web.MethodDescriptor(
  '/cosmos.bank.v1beta1.Query/SupplyOf',
  grpc.web.MethodType.UNARY,
  proto.cosmos.bank.v1beta1.QuerySupplyOfRequest,
  proto.cosmos.bank.v1beta1.QuerySupplyOfResponse,
  /**
   * @param {!proto.cosmos.bank.v1beta1.QuerySupplyOfRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.cosmos.bank.v1beta1.QuerySupplyOfResponse.deserializeBinary
);


/**
 * @param {!proto.cosmos.bank.v1beta1.QuerySupplyOfRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.cosmos.bank.v1beta1.QuerySupplyOfResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.cosmos.bank.v1beta1.QuerySupplyOfResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.cosmos.bank.v1beta1.QueryClient.prototype.supplyOf =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/cosmos.bank.v1beta1.Query/SupplyOf',
      request,
      metadata || {},
      methodDescriptor_Query_SupplyOf,
      callback);
};


/**
 * @param {!proto.cosmos.bank.v1beta1.QuerySupplyOfRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.cosmos.bank.v1beta1.QuerySupplyOfResponse>}
 *     Promise that resolves to the response
 */
proto.cosmos.bank.v1beta1.QueryPromiseClient.prototype.supplyOf =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/cosmos.bank.v1beta1.Query/SupplyOf',
      request,
      metadata || {},
      methodDescriptor_Query_SupplyOf);
};


/**
 * @const
 * @type {!grpc.web.MethodDescriptor<
 *   !proto.cosmos.bank.v1beta1.QueryParamsRequest,
 *   !proto.cosmos.bank.v1beta1.QueryParamsResponse>}
 */
const methodDescriptor_Query_Params = new grpc.web.MethodDescriptor(
  '/cosmos.bank.v1beta1.Query/Params',
  grpc.web.MethodType.UNARY,
  proto.cosmos.bank.v1beta1.QueryParamsRequest,
  proto.cosmos.bank.v1beta1.QueryParamsResponse,
  /**
   * @param {!proto.cosmos.bank.v1beta1.QueryParamsRequest} request
   * @return {!Uint8Array}
   */
  function(request) {
    return request.serializeBinary();
  },
  proto.cosmos.bank.v1beta1.QueryParamsResponse.deserializeBinary
);


/**
 * @param {!proto.cosmos.bank.v1beta1.QueryParamsRequest} request The
 *     request proto
 * @param {?Object<string, string>} metadata User defined
 *     call metadata
 * @param {function(?grpc.web.RpcError, ?proto.cosmos.bank.v1beta1.QueryParamsResponse)}
 *     callback The callback function(error, response)
 * @return {!grpc.web.ClientReadableStream<!proto.cosmos.bank.v1beta1.QueryParamsResponse>|undefined}
 *     The XHR Node Readable Stream
 */
proto.cosmos.bank.v1beta1.QueryClient.prototype.params =
    function(request, metadata, callback) {
  return this.client_.rpcCall(this.hostname_ +
      '/cosmos.bank.v1beta1.Query/Params',
      request,
      metadata || {},
      methodDescriptor_Query_Params,
      callback);
};


/**
 * @param {!proto.cosmos.bank.v1beta1.QueryParamsRequest} request The
 *     request proto
 * @param {?Object<string, string>=} metadata User defined
 *     call metadata
 * @return {!Promise<!proto.cosmos.bank.v1beta1.QueryParamsResponse>}
 *     Promise that resolves to the response
 */
proto.cosmos.bank.v1beta1.QueryPromiseClient.prototype.params =
    function(request, metadata) {
  return this.client_.unaryCall(this.hostname_ +
      '/cosmos.bank.v1beta1.Query/Params',
      request,
      metadata || {},
      methodDescriptor_Query_Params);
};


module.exports = proto.cosmos.bank.v1beta1;

