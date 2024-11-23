import {generateMnemonic, validateMnemonic} from "@/mnemonic/index";

describe(
    'mnemonic unit test case',
    () => {
        test('generate mnemonic', () => {
            const mnemonic = generateMnemonic(15);
            console.log(mnemonic.phrase)
            expect(validateMnemonic(mnemonic.phrase)).toBe(true)
        });
    })