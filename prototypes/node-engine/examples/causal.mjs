// Ordinary functions over a complete authored snapshot. No engine work on import.
import { generatedId } from '../src/calculation-oracle.mjs';
const integer = { type: 'string', pattern: '^(0|-?[1-9][0-9]*)$' };
const field = name => ({ field: name });
const member = (slot, view) => ({ slot, view, partition: [field('group')], order: field('at'), inputs: { amount: field('amount') }, onMissing: 'reject' });
const amountSchema = { type: 'object', additionalProperties: false, properties: { amount: integer, group: {type:'string'}, at: integer }, required: ['amount','group','at'] };
const anchorSchema = { type:'object', additionalProperties:false, properties: {
  sources:{type:'array',items:{type:'string'}}, factor:integer, group:{type:'string'}, at:integer,
  enabled:{type:'boolean'}, range:{type:'boolean'}, parent:{type:'string'},
}, required:['sources','factor','group','at','enabled'] };
export const causalDefinition = {
  name:'causal',version:'1',
  contracts:{ amounts:{version:'1',partition:['id'],order:'integer',inputs:{amount:'integer'},aggregates:{total:{monoid:'sum',input:'amount'},prefix:{monoid:'prefix',input:'amount'}}} },
  views:{effective:{contract:'amounts'},doubled:{contract:'amounts'}},
  models:{
    fact:{schema:amountSchema,memberships:[member('main','effective'),member('first','doubled'),member('second','doubled')]},
    anchor:{schema:anchorSchema,calculations:[{slot:'main',use:'derive'}]},
    adjustment:{schema:anchorSchema,calculations:[{slot:'main',use:'derive'},{slot:'bonus',use:'bonus'}]},
    result:{managed:true,schema:structuredClone(amountSchema),memberships:[member('main','effective')]},
  },
};
export function causalRecord(id, model, data, createdAt='1') {
  return {id,tenant:'t',owner:'o',model,createdAt,data};
}
export function causalAnchor(id,sources,factor='1',extra={}) {
  return causalRecord(id,'anchor',{sources,factor,group:id,at:'1',enabled:true,...extra});
}
export function causalOutput(id, slot='main') { return generatedId('t',id,slot,'value'); }
function implementation(multiplier) {
  return {
    version:'1',
    async resolve({record,readField}) {
      let factor=BigInt(record.data.factor);
      if(record.data.parent) {
        const parent=await readField(record.data.parent,{field:'factor'});
        if(parent.present) factor=BigInt(parent.value);
      }
      const reads=record.data.range
        ? [{slot:'range',kind:'range',view:'effective',partition:[record.data.group],aggregate:'total'}]
        : record.data.sources.map((sourceId,index)=>({slot:`source${index}`,kind:'field',sourceId,selector:{field:'amount'}}));
      return {parameters:{factor:factor*multiplier,enabled:record.data.enabled},reads,
        outputs:[{role:'value',model:'result',owner:record.owner,createdAt:record.createdAt,data:{amount:'0',group:record.data.group,at:record.data.at},computed:['amount']}]};
    },
    evaluate({parameters,values}) {
      let total=0n;
      for(const value of Object.values(values)) {
        if(typeof value==='bigint') total+=value;
        else if(value.present) total+=BigInt(value.value);
      }
      return {outputs:{value:parameters.enabled?{amount:String(total*parameters.factor)}:null}};
    },
  };
}
export function causalCalculations() { return {derive:implementation(1n),bonus:implementation(2n)}; }
export function causalDiamond() {
  return [causalRecord('base','fact',{amount:'10',group:'base',at:'0'}),
    causalAnchor('A',['base'],'2'), causalAnchor('B',['base'],'3'),
    causalAnchor('D',[causalOutput('A'),causalOutput('B')])];
}
