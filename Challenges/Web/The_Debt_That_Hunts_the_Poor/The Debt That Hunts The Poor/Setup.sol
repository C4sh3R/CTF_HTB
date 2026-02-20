// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Token.sol";
import "./LendingPair.sol";

contract Setup {
    address public player;
    bool public isRegister;
    bool public isClaim;
    mapping(address => bool) public yldClaimed;
    bool public testing_var = true;

    Token public immutable USDT;
    Token public immutable YUGEN;
    Token public immutable YUGEN_YLD;
    LendingPair public immutable pair;

    constructor() {
        USDT = new Token("Tether USD","USDT");
        YUGEN = new Token("Axl Token","YUGEN");
        YUGEN_YLD = new Token("YUGEN Yield Share","axlYLD");

        pair = new LendingPair(address(USDT), address(YUGEN), address(YUGEN_YLD));

        require(USDT.transfer(address(pair), 120_000 ether));
        require(YUGEN.transfer(address(pair),  120_000 ether));
    }

    function register(address _player) external payable{
        require(msg.value >= 0.5 ether, "You Need To Pay The Fee First");
        require(!isRegister, "You Already Register");
        player = _player;
        isRegister = true;
    }

    function claim() external {
        require(isRegister, "not registered");
        require(!isClaim, "claimed");
        isClaim = true;

        require(USDT.transfer(msg.sender, 20_000 ether), "USDT fail");
        require(YUGEN.transfer(msg.sender,  20_000 ether), "YUGEN fail");
    }

    function claimYield() external {
        require(pair.isVip(msg.sender), "not VIP");
        require(!yldClaimed[msg.sender], "YLD already claimed");
        yldClaimed[msg.sender] = true;
        YUGEN_YLD.transfer(msg.sender, 20_000 ether);
    }

    function onLiquidationResetYield(address user) external {
        require(msg.sender == address(pair), "only pair");
        yldClaimed[user] = false; 
    }

    /* 
        How the challenge is solved from the backend is by calling this function with the your wallet address.
        You can see what your wallet address is from the info button or from the /api/launch.
    */
    function isSolved(address _player) public view returns(bool){
        // the _player address from the your wallet address that you must make it return true
        if(IERC20(YUGEN).balanceOf(_player) >= 75_000 ether && 
            IERC20(YUGEN_YLD).balanceOf(_player) >= 20_000 ether){
            return true;
        }else{
            return false;
        }
    }

}
