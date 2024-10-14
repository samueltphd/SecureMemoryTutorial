# Setup

```
# clone the repo

git clone https://github.com/gem5/gem5.git --version v23.1.0.0
```
  
```
# initial build

# note: this step takes a while
scons build/<ISA>/gem5.opt -j<num procs>
```
  

## Verify that the build worked!

```
./build/<ISA>/gem5.opt ./configs/example/gem5_library/<isa>-hello.py
```
  

A note about the hello script – in version 23, gem5 started using the “gem5 resources” library to manage external resources such as binaries for syscall emulation mode and kernels/disk images for full system mode. By default, these are downloaded from the gem5 resources website (https://resources.gem5.org/) and stored in `~/.cache/gem5/`. To manage or modify these resources, you can specify your own resources using the call to `obtain_resouce`, specified at `src/python/gem5/resources/resource.py`. I have found this function is slightly less intuitive than it is made out to be… be sure to disable re-downloading on md5 mismatch if you modify any of the resources.

# Build Custom SimObject for Secure Memory Management


Note, there are files that represent all intermediate steps in the repository. First, let’s make a directory where we can build and manage the `SimObject`.

```
mkdir src/mem/secmem-tutorial

# Add SConscript file to allow compilation
touch src/mem/secmem-tutorial/SConscript

## file contents can be found in src/mem/secmem-tutorial/SConscript ##
# change the sources to the v0 versions of the source and header files
```

## Make Python file to declare m5 classes and connect gem5 backend to front-end
```
touch src/mem/secmem-tutorial/SecureMemoryTutorial.py

## file contents can be found in src/mem/secmem-tutorial/SecureMemoryTutorial.py ##
```

Note, if we later want to add runtime parameters to the construction of this object, we can add them to the declaration of the object in this class declaration. When we call the object in the front end, we can pass the parameters to the construction of the `SecureMemory` `SimObject` there.

## Create header and source for custom object

```
## file contents can be found in src/mem/secmem-tutorial/secure_memory_v0.{cc,hh} ##
```

A few notes about the source as currently constructed. We declare our own instantiations of the port class so that we can call the functions associated with the new class on receiving requests/responses to the object. For simplicity, we used the standard ports, but gem5 also has more comprehensive “Queued{Request, Response}Port” classes. We also declare our own stats field that we can use for counting whatever we want.

# Creating Secure Memory Component for Front-End

Once the object has been compiled, we need to build some way of accessing the compiled source in the front end. In the new gem5 library, this is done by adding components and compiling them into front end objects. In particular, these components are located at `src/python/gem5/components`. Let’s start by adding a secure memory component into the front-end accessible memory components.

  
## Add file for the secure memory component

```
## file contents can be found in src/python/gem5/components/memory/secure.py ##
```

This file replicates the `SimpleMemory` object declared in `src/python/gem5/components/memory/simple.py` and creates a callable instance of the `SecureSimpleMemory` (to remain consistent with the callable components in `single_channel.py`). The key component of this class is the creation of the `SecureMemory` object. Note, it is linked to the underlying memory controller through the memory controller port and that the `get_memory_ports` function returns the `cpu_side` port from the `SecureMemory` object. This will allow the cache hierarchy/memory bus to be attached to the `SecureMemory` object before the memory object.

  

Next, we need to be able to compile this new component into the simulator. We do this by adding the following line to `src/python/SConscript` (note, this file is a mess) → `PySource('gem5.components.memory', 'gem5/components/memory/secure.py')` and recompile the simulator.

## Linking custom object into simulation

Let’s test that our newly created back-end object and front-end component can be linked into the simulator. Start by creating a new run script that uses the `SecureSimpleMemory` component that we declared in the prior step. We can do this by calling `from gem5.components.memory.secure import SecureSimpleMemory` and replacing the declaration of the memory device with `SecureSimpleMemory`.

  

See example of this in `configs/example/gem5_library/<isa>-hello-secmemtutorial.py`

  

# Adding Functionality 

Next, add the secure memory functionality! In particular, we'll implement the memory access pattern of a [Bonsai Merkle Tree](https://dl.acm.org/doi/abs/10.1145/1150019.1136502), although we won't implement the actual protocol for incrementing counters, storing hashes, etc for simplicity. We assume that the security metadata is stored at a specially reserved address space above the visible address space from gem5.

Start by adding functions to compute where the metadata addresses for each type are stored. This is done in the `startup()` function, which is declared as virtual in the base `SimObject` class and is called after the constructor for each `SimObject` is completed – this allows us to use the address range for the underlying memory device.
  

After this, we can add functions to compute which precise metadata are to be used for some specific data. We will use these functions to query the memory device for these metadata in particular. These functions are `getParentAddr(uint64_t)` and `getHmacAddr(uint64_t)` and they perform computation on some address. In general, the formula is to figure out the index in the child metadata type and fetches the equivalent index in the parent level (i.e., the parent node in the tree for any data/metadata) divided by the arity of the tree.

If we do this, we break some assumptions about the address range in an abstract memory device. Let’s be sure to turn those assertions off. See these changes in `src/mem/abstract_mem.{cc,hh}` Furthermore, let’s make sure that there is some space to access metadata when we try to fetch it. We do this by creating a buffer for all metadata accesses to load/store from (i.e., `security_metadata`). Because we are only measuring the timing of access, it sufficient for this to be a single block for the purpose of this tutorial.

Next, let’s modify the `handleRequest` and `handleResponse` in our `secure_memory.cc` source to implement the security protocol. When we get a request, we should query memory to fetch the relevant metadata. When we get responses, then we should verify the data and metadata and once the data is verified send it to memory or to the processor.

Finally, let's modify the `handleResponse` call to ensure that all metadata are verified. We authenticate against the root of the tree because it is stored on-chip. Thus, if we receive the response for the root back from the memory device we can assume that our simulated secure memory can authenticate it against the stored value and use that value to verify its children. When some tree node other than the root is returned from memory, we store it in a temporary buffer for `pending_untrusted_packets` for later authentication. When the HMAC fetch returns from memory, we use that value to mark the data as authenticated.

# Next Steps

Here are some natural next steps to follow up from this tutorial!

## Adding a metadata cache

The secure memory protocol typically takes advantage of a cache for metadata. This can be a single cache for all security metadata or one per metadata type. Furthermore, if some metadata fetch hits in the cache, its value is trusted. Try modifying the current implementation to incorporate a metadata cache! Note, this will entail modifying the protocol in the back-end source and modifying the configuration of the `SecureMemorySystem` component.

## Implementing metadata accesses/updates

For simplicity, we didn't implement the actual protocol of maintaining encryption counters, HMACs, and up-to-date tree values. Try modifying the implementation to include this! Note, this will entail updating the `security_metadata` field in `abstract_memory.{cc,hh}` to have space for these addresses.

## Adding additional stats

There is more to know about secure memory! Try updating the stats counters to see if we can glean further takeaways about how secure memory operates under various workloads.

# For Further Questions

Be sure to take advantage of the existing [gem5 mailing archive](), subscribe to the [gem5-users mailing list](), or reach out to the authors of this tutorial!

Samuel Thomas: samuel_thomas@brown.edu
Tamara Lehman: tamara.lehman@colorado.edu

