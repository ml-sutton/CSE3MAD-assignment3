import AsyncStorage from '@react-native-async-storage/async-storage';
import React, { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import { ThemedText } from '@/components/themed-text';
import { ThemedView } from '@/components/themed-view';
import { Colors } from '@/constants/theme';
import { useColorScheme } from '@/hooks/use-color-scheme';
import {
  MESSAGE_STORAGE_KEY,
  decryptPayload,
  encryptAndStorePayload,
  isValidSixDigitPin,
  parsePayloadJson,
  type EncryptedMessagePayload,
} from '@/lib/secure-message';

export default function HomeScreen() {
  const colorScheme = useColorScheme() ?? 'light';
  const tint = Colors[colorScheme].tint;
  const border = colorScheme === 'dark' ? '#3b3f46' : '#dce4eb';
  const surface = colorScheme === 'dark' ? '#1c2127' : '#f4f6f8';
  /** Dark theme uses white `tint` for accents — need dark label on that fill; light theme uses teal + white label. */
  const onPrimaryLabel = colorScheme === 'dark' ? '#11181C' : '#ffffff';

  const [messageText, setMessageText] = useState('');
  const [pin, setPin] = useState('');
  const [unlockSecret, setUnlockSecret] = useState('');

  const [storedPayload, setStoredPayload] = useState<EncryptedMessagePayload | null>(null);
  const [displayPin, setDisplayPin] = useState<string | null>(null);
  const [displayMnemonic, setDisplayMnemonic] = useState<string | null>(null);

  const [decryptedText, setDecryptedText] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadStored = useCallback(async () => {
    try {
      const raw = await AsyncStorage.getItem(MESSAGE_STORAGE_KEY);
      if (!raw) {
        setStoredPayload(null);
        return;
      }
      setStoredPayload(parsePayloadJson(raw));
    } catch {
      setStoredPayload(null);
    }
  }, []);

  useEffect(() => {
    void loadStored();
  }, [loadStored]);

  const onEncryptSave = async () => {
    setError(null);
    setDecryptedText(null);
    setDisplayPin(null);
    setDisplayMnemonic(null);

    if (!messageText.trim()) {
      setError('Enter a message to encrypt.');
      return;
    }
    if (!isValidSixDigitPin(pin)) {
      setError('PIN must be exactly 6 digits.');
      return;
    }

    setBusy(true);
    try {
      const { payload, mnemonic } = await encryptAndStorePayload(messageText, pin);
      await AsyncStorage.setItem(MESSAGE_STORAGE_KEY, JSON.stringify(payload));
      setStoredPayload(payload);
      setDisplayPin(pin);
      setDisplayMnemonic(mnemonic);
      setPin('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Encryption failed.');
    } finally {
      setBusy(false);
    }
  };

  const onDecrypt = async () => {
    setError(null);
    setDecryptedText(null);
    if (!storedPayload) {
      setError('Nothing stored yet. Encrypt a message first.');
      return;
    }
    const secret = unlockSecret.trim();
    if (!secret) {
      setError('Enter your 6-digit PIN or recovery phrase.');
      return;
    }

    setBusy(true);
    try {
      const plain = await decryptPayload(storedPayload, secret);
      setDecryptedText(plain);
      setUnlockSecret('');
    } catch {
      setError('Could not decrypt. Check your PIN or recovery phrase.');
    } finally {
      setBusy(false);
    }
  };

  const onClearStorage = async () => {
    setError(null);
    setDecryptedText(null);
    setDisplayPin(null);
    setDisplayMnemonic(null);
    setBusy(true);
    try {
      await AsyncStorage.removeItem(MESSAGE_STORAGE_KEY);
      setStoredPayload(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <ScrollView
      style={[styles.scroll, { backgroundColor: Colors[colorScheme].background }]}
      contentContainerStyle={styles.scrollContent}
      keyboardShouldPersistTaps="handled"
      keyboardDismissMode="on-drag">
      <ThemedView style={styles.header}>
        <ThemedText type="title">Encrypted message</ThemedText>
        <ThemedText style={styles.muted}>
          Proof of concept for Expo web: your note is saved under AsyncStorage key &quot;message&quot;
          as AES-GCM ciphertext. The data key is wrapped with both your PIN and a new BIP39 phrase so
          you can unlock with either.
        </ThemedText>
      </ThemedView>

      <ThemedView style={[styles.card, { borderColor: border, backgroundColor: surface }]}>
        <ThemedText type="subtitle">1. Write &amp; protect</ThemedText>
        <TextInput
          value={messageText}
          onChangeText={setMessageText}
          placeholder="Message to store encrypted"
          placeholderTextColor={Colors[colorScheme].icon}
          multiline
          style={[styles.input, styles.inputMultiline, { color: Colors[colorScheme].text, borderColor: border }]}
          textAlignVertical="top"
          accessibilityLabel="Message text"
        />
        <TextInput
          value={pin}
          onChangeText={(t) => setPin(t.replace(/\D/g, '').slice(0, 6))}
          placeholder="6-digit PIN"
          placeholderTextColor={Colors[colorScheme].icon}
          keyboardType="number-pad"
          maxLength={6}
          secureTextEntry
          style={[styles.input, { color: Colors[colorScheme].text, borderColor: border }]}
          accessibilityLabel="Six digit PIN"
        />

        <Pressable
          onPress={() => void onEncryptSave()}
          disabled={busy}
          style={({ pressed }) => [
            styles.primaryBtn,
            { backgroundColor: tint, opacity: pressed || busy ? 0.75 : 1 },
          ]}>
          {busy ? (
            <ActivityIndicator color={onPrimaryLabel} />
          ) : (
            <Text style={[styles.btnLabel, { color: onPrimaryLabel }]}>Encrypt &amp; save</Text>
          )}
        </Pressable>

        {storedPayload ? (
          <ThemedText style={styles.hint}>Encrypted payload is saved in storage.</ThemedText>
        ) : null}
      </ThemedView>

      {displayPin && displayMnemonic ? (
        <ThemedView style={[styles.card, styles.reveal, { borderColor: tint, backgroundColor: surface }]}>
          <ThemedText type="subtitle">2. Save these (POC)</ThemedText>
          <ThemedText style={styles.warning}>
            For this demo, your PIN and recovery phrase are shown once. In a real app you would never
            display the PIN; you would only show and back up the phrase.
          </ThemedText>
          <ThemedText type="defaultSemiBold">PIN</ThemedText>
          <ThemedText selectable style={styles.mono}>
            {displayPin}
          </ThemedText>
          <ThemedText type="defaultSemiBold" style={styles.spaced}>
            BIP39 recovery phrase
          </ThemedText>
          <ThemedText selectable style={styles.mono}>
            {displayMnemonic}
          </ThemedText>
        </ThemedView>
      ) : null}

      <ThemedView style={[styles.card, { borderColor: border, backgroundColor: surface }]}>
        <ThemedText type="subtitle">3. Unlock</ThemedText>
        <TextInput
          value={unlockSecret}
          onChangeText={setUnlockSecret}
          placeholder="6-digit PIN or full recovery phrase"
          placeholderTextColor={Colors[colorScheme].icon}
          autoCapitalize="none"
          autoCorrect={false}
          style={[styles.input, styles.inputMultiline, { color: Colors[colorScheme].text, borderColor: border }]}
          accessibilityLabel="PIN or recovery phrase"
        />
        <View style={styles.row}>
          <Pressable
            onPress={() => void onDecrypt()}
            disabled={busy}
            style={({ pressed }) => [
              styles.secondaryBtn,
              { borderColor: tint, opacity: pressed || busy ? 0.75 : 1 },
            ]}>
            {busy ? (
              <ActivityIndicator color={tint} />
            ) : (
              <ThemedText style={[styles.secondaryLabel, { color: tint }]}>Decrypt</ThemedText>
            )}
          </Pressable>
          <Pressable
            onPress={() => void onClearStorage()}
            disabled={busy}
            style={({ pressed }) => [
              styles.ghostBtn,
              { opacity: pressed || busy ? 0.6 : 1 },
            ]}>
            <ThemedText style={styles.danger}>Clear storage</ThemedText>
          </Pressable>
        </View>

        {decryptedText !== null ? (
          <ThemedView style={styles.plainBox}>
            <ThemedText type="defaultSemiBold">Decrypted message</ThemedText>
            <ThemedText selectable style={styles.plainText}>
              {decryptedText}
            </ThemedText>
          </ThemedView>
        ) : null}
      </ThemedView>

      {error ? (
        <ThemedText style={styles.err} accessibilityLiveRegion="polite">
          {error}
        </ThemedText>
      ) : null}

      {Platform.OS === 'web' ? (
        <ThemedText style={[styles.muted, styles.footer]}>
          Running on web: storage maps to localStorage. Use localhost or HTTPS so Web Crypto (AES-GCM /
          PBKDF2) is available.
        </ThemedText>
      ) : null}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scroll: {
    flex: 1,
  },
  scrollContent: {
    padding: 20,
    paddingBottom: 40,
    maxWidth: 640,
    width: '100%',
    alignSelf: 'center',
  },
  header: {
    marginBottom: 16,
    gap: 8,
  },
  muted: {
    opacity: 0.85,
    fontSize: 15,
    lineHeight: 22,
  },
  card: {
    borderWidth: 1,
    borderRadius: 12,
    padding: 16,
    gap: 10,
    marginBottom: 16,
  },
  reveal: {
    borderWidth: 2,
  },
  input: {
    borderWidth: 1,
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: Platform.select({ web: 10, default: 8 }),
    fontSize: 16,
    minHeight: 44,
  },
  inputMultiline: {
    minHeight: 100,
    paddingTop: 12,
  },
  primaryBtn: {
    borderRadius: 10,
    paddingVertical: 14,
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: 48,
  },
  btnLabel: {
    fontSize: 16,
    fontWeight: '600',
  },
  secondaryBtn: {
    flex: 1,
    borderWidth: 2,
    borderRadius: 10,
    paddingVertical: 12,
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: 48,
  },
  secondaryLabel: {
    fontSize: 16,
    fontWeight: '600',
  },
  row: {
    flexDirection: 'row',
    gap: 12,
    alignItems: 'center',
    flexWrap: 'wrap',
  },
  ghostBtn: {
    paddingVertical: 12,
    paddingHorizontal: 8,
  },
  danger: {
    color: '#c43c3c',
    fontSize: 15,
    fontWeight: '600',
  },
  hint: {
    fontSize: 13,
    opacity: 0.8,
  },
  warning: {
    fontSize: 14,
    lineHeight: 20,
    opacity: 0.9,
  },
  mono: {
    fontFamily: Platform.select({ web: 'ui-monospace, monospace', default: 'monospace' }),
    fontSize: 15,
    lineHeight: 22,
  },
  spaced: {
    marginTop: 8,
  },
  plainBox: {
    marginTop: 8,
    gap: 6,
  },
  plainText: {
    fontSize: 16,
    lineHeight: 24,
  },
  err: {
    color: '#c43c3c',
    marginBottom: 12,
    fontSize: 15,
  },
  footer: {
    marginTop: 8,
  },
});
