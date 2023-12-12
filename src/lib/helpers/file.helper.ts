import fs from 'fs';
import path from 'path';
import moment from 'moment';
import { promises as fsp } from 'fs';
import { SSVKeysException } from '../../lib/exceptions/base';

/**
 * Read file contents and return json data from it.
 * @param filePath
 * @param json
 */
export const readFile = async (filePath: string, json=true): Promise<any> => {
  return fsp.readFile(filePath, { encoding: 'utf-8' }).then((data) => {
    return json ? JSON.parse(data) : data;
  });
}

/**
 * Write file contents.
 * @param filePath
 * @param data
 */
export const writeFile = async (filePath: string, data: string): Promise<any> => {
  fsp.writeFile(filePath, data, { encoding: 'utf-8' });
}

/**
 * Create SSV keys directory to work in scope of in user home directory
 */
export const createSSVDir = async (outputFolder: string): Promise<any> => {
  return fsp.mkdir(outputFolder, { recursive: true });
}

/**
 * Get SSV keys directory to work in scope of in user home directory.
 * Create it before, if it doesn't exist.
 */
export const getSSVDir = async (outputFolder: string): Promise<string> => {
  if (!fs.existsSync(outputFolder)) {
    await createSSVDir(outputFolder);
  }
  return outputFolder.endsWith(path.sep) ? outputFolder : `${outputFolder}${path.sep}`;
}

export const getFilePath = async (name: string, outputFolder: string, withTime = true): Promise<string> => {
  return `${await getSSVDir(outputFolder)}${name}${withTime ? `-${moment().unix()}` : ''}.json`;
}

export type KeyStoreFilesResult = {
  files: string[];
  isFolder: boolean;
}

export const getKeyStoreFiles = async (keystorePath: string): Promise<KeyStoreFilesResult> => {
  const stat = await fsp.stat(keystorePath);
  const isFolder = stat.isDirectory();

  let files;
  if (isFolder) {
    const folderContent = await fsp.readdir(keystorePath);
    if (folderContent.length === 0) {
      throw new SSVKeysException('No keystore files detected. Please provide a folder with correct keystore files and try again.');
    }
    files = folderContent.map(file => path.join(keystorePath, file)).sort();
  } else {
    files = [keystorePath];
  }
  return { files, isFolder };
}
