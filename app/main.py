import json
import sy
import bencodepy
import requests
import sys



# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    def extract_string(data):
        length, rest = data.split(b":",1)
        length = int(length)
        return rest[:length], rest[length:]
    # Recursive decode function
    def decode(data):
        if data[0:1].isdigit():# byte string like b"5:hello"
            decoded_str, rest =  extract_string(data) 
            return decoded_str, rest
        elif data.startswith(b'i'): # integer like b'i42e'
            end = data.index(b'e')
            return int(data[1:end]), data[end+1:]
        elif data.startswith(b'l'):
            data = data[l:]
            result = []
            # Technically only recursive if we have nested lists
            while not data.startswith(b'e'):
                item, data = decode(data)
                result.append(item)
            return result, data[1:]
        else:
            raise ValueError("Unsupported or invalid bencoded value")
    deecoded_value, _ = decode(bencoded_value)
    return deecoded_value
        
    

def main():
    command = sys.argv[1]

    


    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
