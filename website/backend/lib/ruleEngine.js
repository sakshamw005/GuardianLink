const OPERATORS = {
  eq: (a, b) => a === b,
  neq: (a, b) => a !== b,
  gt: (a, b) => typeof a === 'number' && a > b,
  gte: (a, b) => typeof a === 'number' && a >= b,
  lt: (a, b) => typeof a === 'number' && a < b,
  lte: (a, b) => typeof a === 'number' && a <= b,
  in: (a, b) => Array.isArray(b) && b.includes(a),
  contains: (a, b) =>
    typeof a === 'string' && a.toLowerCase().includes(b.toLowerCase()),
  any: (a, b) =>
    Array.isArray(b) && b.some(v => a?.toString().toLowerCase().includes(v)),
  exists: a => a !== undefined && a !== null
};

function evaluateRule(rule, signals) {
  for (const cond of rule.conditions) {
    const { field, op, value } = cond;
    const signalValue = signals[field];

    const operator = OPERATORS[op];
    if (!operator) return false;

    if (!operator(signalValue, value)) {
      return false;
    }
  }
  return true;
}

module.exports = { evaluateRule };
