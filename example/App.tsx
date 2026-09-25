import CSRModule, { ECCurve } from '@generacclean/react-native-ecc-csr';
import { useState } from 'react';
import { Button, SafeAreaView, ScrollView, StyleSheet, Text, View } from 'react-native';

const ALIAS = 'ecc_csr_example_key';

// A manual harness for device checks: each button calls one native function and prints the
// result, or the rejection's code and message, so behaviour can be compared across platforms.
export default function App() {
  const [log, setLog] = useState<string[]>([]);

  async function run(label: string, call: () => Promise<unknown>) {
    const started = Date.now();
    try {
      const result = await call();
      append(`✅ ${label} (${Date.now() - started} ms)\n${JSON.stringify(result, null, 2)}`);
    } catch (e) {
      const { code, message } = e as { code?: string; message?: string };
      append(`❌ ${label} (${Date.now() - started} ms)\n${code}: ${message}`);
    }
  }

  function append(entry: string) {
    setLog((previous) => [entry, ...previous]);
  }

  function generate(curve: ECCurve, useHardwareKey: boolean) {
    return run(`generateCSR ${curve}${useHardwareKey ? ' (hardware)' : ''}`, () =>
      CSRModule.generateCSR({
        country: 'US',
        state: 'Wisconsin',
        locality: 'Waukesha',
        organization: 'Generac Power Systems',
        organizationalUnit: 'Field Pro',
        commonName: 'ecc-csr-example',
        ipAddress: '10.10.10.10',
        curve,
        privateKeyAlias: ALIAS,
        useHardwareKey,
      })
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.buttons}>
        <Button title="Capabilities" onPress={() => run('getHardwareKeystoreCapabilities', CSRModule.getHardwareKeystoreCapabilities)} />
        <Button title="P-256 hardware" onPress={() => generate('secp256r1', true)} />
        <Button title="P-384" onPress={() => generate('secp384r1', false)} />
        <Button title="P-521" onPress={() => generate('secp521r1', false)} />
        <Button title="keyExists" onPress={() => run('keyExists', () => CSRModule.keyExists(ALIAS))} />
        <Button title="getPublicKey" onPress={() => run('getPublicKey', () => CSRModule.getPublicKey(ALIAS))} />
        <Button title="deleteKey" onPress={() => run('deleteKey', () => CSRModule.deleteKey(ALIAS))} />
        <Button title="Clear" onPress={() => setLog([])} />
      </View>
      <ScrollView style={styles.log}>
        {log.map((entry, index) => (
          <Text key={log.length - index} selectable style={styles.entry}>
            {entry}
          </Text>
        ))}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#fff' },
  buttons: { flexDirection: 'row', flexWrap: 'wrap', padding: 8 },
  log: { flex: 1, paddingHorizontal: 12 },
  entry: { fontFamily: 'Courier', fontSize: 11, marginBottom: 12 },
});
