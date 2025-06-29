import asyncio


async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"Connection from {addr}")

    while True:
        data = await reader.read(1000)  # Read up to 100 bytes
        if not data:
            break
        message = data.decode()
        a, p = addr
        with open(f"{a}#{p}", "a") as log_file:
            log_file.write(message)

        print(f"Received: {message} from {addr}")
        writer.write(data.upper())
        await writer.drain()

    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", 8923)
    print("Server running on 0.0.0.0:8888")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())