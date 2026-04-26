const nativeBinding = require('./swh-client.node');

// 명시적으로 SwhCore를 추출하여 내보냅니다.
const { SwhCore } = nativeBinding;

module.exports = nativeBinding;
module.exports.SwhCore = SwhCore;
