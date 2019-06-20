import frida
import sys
import os

def read_file_as_str(file_path):
    if not os.path.isfile(file_path):
        raise TypeError(file_path + " does not exist")

    all_the_text = open(file_path).read()
#     print type(all_the_text)
    return all_the_text

def write_messages(message, data):
    print(message['payload'])
    dexfile = open("./classes.dex1", "ab+") # you need modify
    dexfile.write(data)
    

def hook_define_class():
	# you need change next line to tell program finding the file of dumpdex.js  
    hook_js = read_file_as_str("./dumpdex.js")
    #print hook_js

    return hook_js

def main(apk):
    
    device = frida.get_usb_device(10)
    pid = device.spawn([apk])
    session = device.attach(pid)
    device.resume(pid)
    script = session.create_script(hook_define_class())
    script.on('message', write_messages)
    script.load()
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main("com.example.hello") # you need modify

    sys.exit(0)

    