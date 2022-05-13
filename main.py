from padding_oracle_attack import PaddingOracle, decode


def main():
    ciphertext = "7cd48a82223c2e3896d6898050f5a69bf8dce223cf5164962b15dddcda325b66ba120d6b3f299aaa6e20e04512b99ab387a9e969d717f8d3612bfc051ff289c8"
    target = "http://crypto-class.appspot.com/po?er="

    po = PaddingOracle(target)
    raw_decryption = po.decrypt4blocks(ciphertext)
    message = decode(raw_decryption)
    print("Final result: ", message)


if __name__ == "__main__":
    main()
