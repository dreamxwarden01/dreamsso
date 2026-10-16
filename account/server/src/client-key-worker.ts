import {applyClientKeyOperationLocked} from './client-key-state.js';

// Called only by the fixed /usr/bin/flock command. Private material stays in the
// protected state file and process memory; stdout is deliberately metadata-free.
try {
  const [operation,file,...extra]=process.argv.slice(2);
  if(process.platform!=='linux'||extra.length||!file||(operation!=='schedule'&&operation!=='reconcile'))throw Error();
  applyClientKeyOperationLocked(file,operation);
  process.stdout.write('{"ok":true}\n');
} catch {
  process.stdout.write('{"ok":false}\n');
  process.exitCode=1;
}
