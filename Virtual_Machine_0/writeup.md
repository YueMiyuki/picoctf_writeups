# Virtual Machine 0

## Category
Reverse Engineering

## Difficulty
Easy

## What is that
A mechanical analog computer (LEGO gear mechanism) where red axle rotation is input and blue axle is output. Given a large input number, find the output.

## Solve

The challenge provides a `.dae` file describing the LEGO gear mechanism. See the geometry definitions reveals two gear parts:

```xml
<geometry id="3647.json-mesh" name="3647.json">  <!-- LEGO part 3647: 8-tooth gear -->
<geometry id="3649.json-mesh" name="3649.json">  <!-- LEGO part 3649: 40-tooth gear -->
```

In the scene graph, the 40-tooth gear meshes with an 8-tooth gear on the same gear train:

```xml
<node id="Part_3" name="Part.3" type="NODE">
    <matrix sid="transform">1 0 0 -8 0 1 0 36 0 0 1 12 0 0 0 1</matrix>
    <instance_geometry url="#3647.json-mesh">  <!-- 8-tooth gear -->
        ...
    </instance_geometry>
</node>
<node id="Part_7" name="Part.7" type="NODE">
    <matrix sid="transform">1 0 0 -8 0 1 0 36 0 0 1 4 0 0 0 1</matrix>
    <instance_geometry url="#3649.json-mesh">  <!-- 40-tooth gear -->
        ...
    </instance_geometry>
</node>
```

Both sit at the same Y=36 position on the same axle assembly, confirming they mesh together. The ratio is 40/8 = **5:1**, the output (blue) axle rotates 5 times for each input (red) rotation.

**Formula**: `output = input × 5`

```python
inp = 39722847074734820757600524178581224432297292490103995908738058203639164185
output = inp * 5
flag = output.to_bytes((output.bit_length() + 7) // 8, 'big').decode('ascii')
print(flag)  # picoCTF{g34r5_0f_m0r3_3537e50a}
```

## Flag
`picoCTF{g34r5_0f_m0r3_3537e50a}`
