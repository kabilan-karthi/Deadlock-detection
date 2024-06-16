import streamlit as st
import hashlib
import time
import threading
from queue import Queue

# Define the block structure
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        sha = hashlib.sha256()
        sha.update(str(self.index).encode('utf-8') +
                   str(self.timestamp).encode('utf-8') +
                   str(self.data).encode('utf-8') +
                   str(self.previous_hash).encode('utf-8'))
        return sha.hexdigest()

# Define the blockchain
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.lock_list = {}
        self.deadlock_detected = False

    def create_genesis_block(self):
        return Block(0, time.time(), "Genesis Block", "0")

    def add_block(self, block):
        self.chain.append(block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

    def acquire_lock(self, process, resource):
        if resource in self.lock_list:
            if self.lock_list[resource] == process:
                return True
            else:
                self.deadlock_detected = True
                return False
        else:
            self.lock_list[resource] = process
            return True

    def release_lock(self, process, resource):
        if resource in self.lock_list and self.lock_list[resource] == process:
            del self.lock_list[resource]
            return True
        else:
            return False

# Streamlit app
def main():
    st.title("Deadlock Avoidance using Blockchain")

    # Initialize the blockchain
    blockchain = Blockchain()

    # Get user input
    resources = st.text_input("Enter the resources (comma-separated)", "R1, R2, R3")
    processes = st.text_input("Enter the processes (comma-separated)", "P1, P2, P3")
    actions = st.text_area("Enter the actions (one per line, format: <process> <action> <resource>)", """
    P1 ACQUIRE R1
    P2 ACQUIRE R2
    P1 RELEASE R1
    P3 ACQUIRE R3
    P2 RELEASE R2
    P3 RELEASE R3
    """)

    if st.button("Execute Actions"):
        # Parse the actions
        action_list = actions.strip().split('\n')
        action_queue = Queue()

        for action in action_list:
            action_queue.put(action)

        def process_actions():
            while not action_queue.empty():
                action = action_queue.get()
                process, action_type, resource = action.split()
                if action_type == "ACQUIRE":
                    if blockchain.acquire_lock(process, resource):
                        block = Block(len(blockchain.chain), time.time(), f"{process} acquired {resource}", blockchain.chain[-1].hash)
                        blockchain.add_block(block)
                        st.write(f"{process} acquired {resource}")
                    else:
                        st.write(f"**Deadlock detected! {process} cannot acquire {resource}. Suggestion: Release {resource} from {blockchain.lock_list[resource]}**")
                elif action_type == "RELEASE":
                    if blockchain.release_lock(process, resource):
                        block = Block(len(blockchain.chain), time.time(), f"{process} released {resource}", blockchain.chain[-1].hash)
                        blockchain.add_block(block)
                        st.write(f"{process} released {resource}")
                    else:
                        st.write(f"**Error: {process} does not hold the lock for {resource}.**")

        # Create and start threads for each action
        threads = []
        for _ in range(len(action_list)):
            thread = threading.Thread(target=process_actions)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Check the validity of the blockchain
        if blockchain.is_chain_valid():
            st.write("**Blockchain is valid.**")
        else:
            st.write("**Blockchain is invalid. Potential deadlock detected.**")

        # Display the blockchain
        st.write("### Blockchain")
        for block in blockchain.chain:
            st.write(f"**Index:** {block.index}")
            st.write(f"**Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(block.timestamp))}")
            st.write(f"**Data:** {block.data}")
            st.write(f"**Previous Hash:** {block.previous_hash}")
            st.write(f"**Hash:** {block.hash}")
            st.write("---")

        # Display the lock list
        st.write("### Resource Lock Status")
        for resource, process in blockchain.lock_list.items():
            st.write(f"**{resource}:** Locked by {process}")

        # Notify about deadlock
        if blockchain.deadlock_detected:
            st.error("Deadlock occurred during the execution of actions.")

if __name__ == "__main__":
    main()
