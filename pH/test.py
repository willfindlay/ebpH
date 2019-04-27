from time import sleep

while True:
    try:
        sleep(1)
        print("testificate")
    except KeyboardInterrupt:
        print("keyboard interrupt received")
