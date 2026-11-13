import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareCatalog, validateRecord, projectRecord } from '../src/catalog.mjs';

function definition() {
  const membership = { slot: 'main', view: 'effective', partition: [{field:'accountId'}, {header:'owner'}], order: {field:'at'}, inputs: {amount: {field:'amount'}}, onMissing:'reject' };
  return { name:'ledger', version:'1', contracts: { balance: { version:'1', partition:['id','id'], order:'integer', inputs:{amount:'integer'}, aggregates:{total:{monoid:'sum',input:'amount'}, balance:{monoid:'prefix',input:'amount'}} } }, views:{effective:{contract:'balance'},created:{contract:'balance'}}, models:{account:{schema:{type:'object',properties:{},additionalProperties:false}},issue:{schema:{type:'object',properties:{accountId:{type:'string'},at:{type:'string'},amount:{type:'string'},optional:{type:'string'}},required:['accountId','at','amount'],additionalProperties:false},references:[{slot:'account',field:'accountId',targets:['account'],many:false,onDelete:'reject'}],uniqueness:[{slot:'pair',fields:[{field:'accountId'},{header:'owner'}]}],memberships:[membership,{...membership,slot:'second'},{...membership,slot:'created',view:'created',order:{header:'createdAt'}}]}} };
}
const record = () => ({id:'r',tenant:'t',owner:'o',model:'issue',createdAt:'2',data:{accountId:'a',at:'9007199254740993',amount:'-9007199254740993'}});

test('immutable catalog projects exact values, multiple slots and distinct named views', () => {
  const declaration = definition(), prepared = prepareCatalog(declaration);
  declaration.models.issue.memberships[0].view = 'created';
  assert.equal(prepared.definition.models.issue.memberships[0].view, 'effective');
  assert.ok(Object.isFrozen(prepared.definition.models.issue.schema.properties));
  assert.notEqual(prepared.views.effective.identity, prepared.views.created.identity);
  const occurrences = projectRecord(prepared, record());
  assert.equal(occurrences.length, 3);
  assert.deepEqual(occurrences.map(o => o.slot), ['main','second','created']);
  assert.deepEqual(occurrences[0].partition, ['a','o']);
  assert.equal(occurrences[0].order, 9007199254740993n);
  assert.equal(occurrences[0].contributions.total, -9007199254740993n);
  assert.equal(occurrences[2].order, 2n);
  const input = record(), detached = validateRecord(prepared,input); detached.data.amount = '8'; assert.equal(input.data.amount,'-9007199254740993');
});

test('identity ignores property order and includes declaration and implementation versions', () => {
  const a = definition(), b = JSON.parse(JSON.stringify(a));
  b.models.issue.schema.properties = Object.fromEntries(Object.entries(b.models.issue.schema.properties).reverse());
  assert.equal(prepareCatalog(a).identity, prepareCatalog(b).identity);
  b.models.issue.memberships[0].order = {header:'createdAt'};
  assert.notEqual(prepareCatalog(a).identity, prepareCatalog(b).identity);
  const c = definition(); c.views.other = {contract:'balance'};
  assert.notEqual(prepareCatalog(a).identity, prepareCatalog(c).identity);
  const beforeContract = prepareCatalog(c);
  c.contracts.balance.version = '2'; assert.notEqual(prepareCatalog(a).identity, prepareCatalog(c).identity);
  assert.notEqual(beforeContract.views.effective.identity, prepareCatalog(c).views.effective.identity);
});

test('malformed binding declarations and unknown reference targets reject at preparation', () => {
  for (const change of [
    d => d.models.issue.memberships.push(d.models.issue.memberships[0]),
    d => d.models.issue.memberships[0].partition.pop(),
    d => d.models.issue.memberships[0].inputs.amount = {field:'missing'},
    d => d.models.issue.memberships[0].order = {field:'at',constant:'1'},
    d => d.models.issue.memberships[0].view = 'unknown',
    d => d.models.issue.references[0].targets = ['unknown'],
    d => d.models.issue.schema.properties.amount = {type:'integer'},
    d => d.contracts.balance.aggregates.total.monoid = 'unknown',
    d => d.models.issue.dependencies = [{field:'amount'}],
    d => d.models.issue.schema.$async = true,
  ]) { const d = definition(); change(d); assert.throws(() => prepareCatalog(d)); }
});

test('missing optional selectors skip only by policy; invalid and null values never skip', () => {
  const d = definition(); d.models.issue.memberships = [{...d.models.issue.memberships[0], inputs:{amount:{field:'optional'}},onMissing:'skip'}];
  const p = prepareCatalog(d);
  assert.deepEqual(projectRecord(p,record()),[]);
  for (const optional of ['01',null,'bad']) { const r=record(); r.data.optional=optional; assert.throws(() => projectRecord(p,r)); }
  d.models.issue.memberships[0].onMissing='reject'; assert.throws(() => projectRecord(prepareCatalog(d),record()));
});

test('source wire shape rejects unsafe numbers, unknown headers and malformed headers/data', () => {
  const p = prepareCatalog(definition());
  for (const change of [r=>r.extra=true,r=>r.owner='',r=>r.createdAt=2,r=>r.data.amount=9007199254740992,r=>r.data.extra=true,r=>r.model='unknown',r=>r.data.at='01',r=>r.id='\ud800']) {
    const r=record(); change(r); assert.throws(()=>projectRecord(p,r));
  }
});

test('identity pins used validator and monoid versions without hashing functions', () => {
  const d=definition(); d.contracts.balance.validators=[{scope:'root',use:'positive'}];
  const validators={positive:{version:'1',validate:()=>true}};
  const a=prepareCatalog(d,{validators});
  assert.equal(a.identity,prepareCatalog(d,{validators:{positive:{version:'1',validate:()=>false}}}).identity);
  assert.notEqual(a.identity,prepareCatalog(d,{validators:{positive:{version:'2',validate:()=>true}}}).identity);
});
