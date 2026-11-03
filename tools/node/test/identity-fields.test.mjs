import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeIdentityFields } from '../private/identity-fields.mjs';
import { normalizeEmailAddress } from '../private/email-plan.mjs';
import { prepareModel } from '../model.mjs';

test('identity email normalizes the whole address and leaves source inputs untouched', () => {
  const fields = Object.freeze({ kind: 'email', value: ' Alice+News@EXAMPLE.COM ' });
  const normalized = normalizeIdentityFields(fields);
  assert.deepEqual(normalized, { kind: 'email', value: 'alice+news@example.com' });
  assert.equal(fields.value, ' Alice+News@EXAMPLE.COM ');
  assert.deepEqual(normalizeIdentityFields(normalized, { requireCanonical: true }), normalized);
  assert.throws(() => normalizeIdentityFields(fields, { requireCanonical: true }), { code: 'invalid_identity' });
  assert.equal(normalizeEmailAddress('Alice@EXAMPLE.COM'), 'Alice@example.com');
  const boundary = `${'a'.repeat(64)}@${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`;
  assert.equal(boundary.length, 254);
  assert.equal(normalizeIdentityFields({ kind: 'email', value: boundary }).value, boundary);
  assert.throws(() => normalizeIdentityFields({ kind: 'email', value: `${boundary}d` }), { code: 'invalid_identity' });
});

test('identity phone preserves exact E164 digits and rejects country guesses and control trimming', () => {
  for (const value of ['+12345678', '+123456789012345', ' +919876543210 ']) {
    const normalized = normalizeIdentityFields({ kind: 'phone', value });
    assert.equal(normalized.value, value.trim());
    assert.deepEqual(normalizeIdentityFields(normalized, { requireCanonical: true }), normalized);
  }
  for (const value of ['+1234567', '+1234567890123456', '+012345678', '1234567890',
    '+1 23456789', '+1-23456789', '+123456789x1', '+１２３４５６７８', '\t+123456789',
    '+123456789\r', '\u00a0+123456789', '', '+']) {
    assert.throws(() => normalizeIdentityFields({ kind: 'phone', value }), { code: 'invalid_identity' }, value);
  }
});

test('identity fields reject forged system state and malformed mailbox syntax', () => {
  for (const fields of [null, [], ['email', 'a@example.com'], { kind: 'email' },
    { value: 'a@example.com' }, { kind: 'email', value: null }, { kind: 'Email', value: 'a@example.com' },
    { kind: { email: null }, value: 'a@example.com' },
    { kind: 'email', value: 'a@example.com', identity_revision: '1' },
    { kind: 'email', value: 'a@example.com', verified_revision: '1' }]) {
    assert.throws(() => normalizeIdentityFields(fields), { code: 'invalid_identity' });
  }
  for (const value of ['', ' ', 'Alice <alice@example.com>', 'a@example.com,b@example.com',
    'a(comment)@example.com', 'a..b@example.com', '.a@example.com', 'a.@example.com',
    'a@example..com', 'a@-example.com', 'a@example-.com', 'a@example.com@evil.test',
    ' a@example.com\t', '\na@example.com', 'a\0@example.com', 'é@example.com', 'a@éxample.com',
    '\u00a0a@example.com', `${'a'.repeat(65)}@example.com`]) {
    assert.throws(() => normalizeIdentityFields({ kind: 'email', value }), { code: 'invalid_identity' }, value);
  }
});

test('prepared fixtures and native validation normalize only the declared identity resource', async () => {
  const identitySchema = { $schema: 'https://json-schema.org/draft/2020-12/schema', type: 'object', required: ['kind', 'value'], additionalProperties: false,
    properties: { kind: { const: 'phone' }, value: { type: 'string', pattern: '^\\+[1-9][0-9]{7,14}$' } } };
  const catalog = { model: 'a'.repeat(64), capabilities: { identities: { contract: 1003 } },
    contracts: [{ code: 1003, name: 'Identity', visibility: 'public', schema: identitySchema }] };
  const id = '00000000-0000-0000-0000-000000000001';
  const calls = [];
  const native = { selection: { model: catalog.model, selector: 'services' }, validate: async params => { calls.push(params); return params; } };
  const model = prepareModel(catalog, { selector: 'services', native });
  const fields = { kind: 'phone', value: ' +12345678 ' };
  assert.equal(model.draftFixture([{ contract: 'Identity', id, fields }]).commands[0].fields.value, '+12345678');
  assert.equal((await model.validateNative(1003, fields)).input.value, '+12345678');
  assert.equal(fields.value, ' +12345678 ');
  assert.equal(calls.length, 1);
  const ordinary = prepareModel({ ...catalog, capabilities: {} }, { selector: 'services' });
  assert.throws(() => ordinary.draftFixture([{ contract: 'Identity', id, fields }]), /schema/);
});
