import { NativeModules } from 'react-native';

const { CSRModule } = NativeModules;

export type ECCurve = 'secp256r1' | 'secp384r1' | 'secp521r1';

export interface CSRParams {
  country?: string;
  state?: string;
  locality?: string;
  organization?: string;
  organizationalUnit?: string;
  commonName: string;
  serialNumber?: string;
  ipAddress?: string;
  dnsName?: string;
  curve?: ECCurve;
  privateKeyAlias: string;
  phoneInfo?: string;
  useHardwareKey?: boolean;
}

export interface CSRResult {
  csr: string;
  privateKeyAlias: string;
  publicKey: string;
  isHardwareBacked: boolean;
  useHardwareKey: boolean;
  hardwareKeyRequested: boolean;
  tlsCompatible: boolean;
}

export interface HardwareKeystoreCapabilities {
  tlsCompatible: boolean;
  androidSdkVersion: number;
  hasStrongBox: boolean;
  manufacturer: string;
  model: string;
  device: string;
}

export interface CSRModuleInterface {
  /**
   * Generates a Certificate Signing Request (CSR) with ECC key pair.
   * The module intelligently decides hardware vs software backing based on device capabilities.
   * Apps can request hardware keys via useHardwareKey parameter, but the module will override
   * this if the device doesn't support hardware keys for TLS (requires Android 12+).
   *
   * @param params - CSR parameters including privateKeyAlias and optional useHardwareKey
   * @returns Promise resolving to CSR, key alias, public key, and key storage info
   */
  generateCSR(params: CSRParams): Promise<CSRResult>;

  /**
   * Checks if the device supports hardware-backed keys for TLS.
   * Apps should call this before requesting hardware keys to understand device capabilities.
   *
   * @returns Promise resolving to device capability information
   */
  getHardwareKeystoreCapabilities(): Promise<HardwareKeystoreCapabilities>;

  /**
   * Deletes a key from both hardware and software keystores
   * @param privateKeyAlias - The alias of the key to delete
   * @returns Promise resolving to true if key was deleted
   */
  deleteKey(privateKeyAlias: string): Promise<boolean>;

  /**
   * Checks if a key exists in either hardware or software keystore
   * @param privateKeyAlias - The alias of the key to check
   * @returns Promise resolving to true if key exists
   */
  keyExists(privateKeyAlias: string): Promise<boolean>;

  /**
   * Retrieves the public key for a given alias from either keystore
   * @param privateKeyAlias - The alias of the key pair
   * @returns Promise resolving to base64-encoded public key
   */
  getPublicKey(privateKeyAlias: string): Promise<string>;
}

export default CSRModule as CSRModuleInterface;
